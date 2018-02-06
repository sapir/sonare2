import _ from 'lodash';
import React, { Component } from 'react';
import dagre from 'dagre';


export default class BlockGraph extends Component {

  renderAsmToken(asmLine, token, i) {
    let className = `token-${token.type}`;

    if (token.type === "operand") {
      const op = asmLine.operands[token.index];
      className += ` token-operand-${op.type}`;

      if (token.part_type !== "full") {
        className += ` token-operand-${op.type}-${token.part_type}`;
      }
    }

    return (
      <span key={i} className={className}>
        {token.string}
      </span>
    );
  }

  renderAsmLine(asmLine) {
    return (
      <div key={asmLine.start}>
        {_.map(asmLine.tokens, (token, i) => this.renderAsmToken(asmLine, token, i))}
      </div>
    );
  }

  renderBlock(block, asmLinesByAddress) {
    const asmLines = _.map(
      block.opcodes, address => asmLinesByAddress[address]);

    return (
      <div key={block.address}>
        <h5>Block @ {block.address.toString(16)}</h5>
        {_.map(asmLines, asmLine => this.renderAsmLine(asmLine))}
      </div>
    );
  }

  render() {
    if (!this.props.func || !this.props.func.blocks)
      return <div />;

    const asmLinesByAddress = _.fromPairs(
      _.map(
        this.props.func ? this.props.func.asm_lines : [],
        asmLine => [asmLine.start, asmLine]));

    const g = new dagre.graphlib.Graph();
    g.setGraph({});
    g.setDefaultEdgeLabel(() => ({}));

    let blocksByAddress = {};

    for (let block of this.props.func.blocks) {
      blocksByAddress[block.address] = block;

      // TODO: width & height
      g.setNode(block.address, {width: 100, height: 100});
      for (let toAddr of block.flow) {
        g.setEdge(block.address, toAddr);
      }
    }

    dagre.layout(g);

    const nodes = g.nodes();
    const nodeLabels = _.map(nodes, nodeID => g.node(nodeID));

    const minX = _.min(_.map(nodeLabels, n => n.x));
    const minY = _.min(_.map(nodeLabels, n => n.y));

    // TODO: center graph in viewport instead, enlarge as necessary
    // move nodes so that top-left is at (0, 0)
    for (let n of nodeLabels) {
      n.x -= minX;
      n.y -= minY;
    }

    const graphWidth = _.max(_.map(nodeLabels, n => n.x + n.width));
    const graphHeight = _.max(_.map(nodeLabels, n => n.y + n.height));

    return (
      <svg width={graphWidth} height={graphHeight}>
        <g>
          {_.map(nodes, nodeID => {
            let node = g.node(nodeID);
            let {x, y, width, height} = node;
            return (
              <g key={nodeID} transform={`translate(${x},${y})`}>
                <rect
                  width={width}
                  height={height}
                  fill="#4286f4"
                  stroke="black"
                  />

                <foreignObject width={width} height={height}>
                  {this.renderBlock(
                    blocksByAddress[nodeID], asmLinesByAddress)}
                </foreignObject>
              </g>
            );
          })}

          {_.map(g.edges(), ({v, w}) => {
            let nodeA = g.node(v);
            let nodeB = g.node(w);
            const x1 = nodeA.x + nodeA.width / 2;
            const y1 = nodeA.y + nodeA.height / 2;

            const x2 = nodeB.x + nodeB.width / 2;
            const y2 = nodeB.y + nodeB.height / 2;

            return (
              <line
                key={[v, w]}
                x1={x1} y1={y1} x2={x2} y2={y2}
                strokeWidth={2} stroke="black"
                />
            );
          })}
        </g>
      </svg>
    );
  }
}