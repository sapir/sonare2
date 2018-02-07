import _ from 'lodash';
import React, { Component } from 'react';
import update from 'immutability-helper';
import dagre from 'dagre';
import Measure from 'react-measure';
import BasicBlock from './BasicBlock';


export default class BlockGraph extends Component {
  constructor(props) {
    super(props);
    // TODO: clear blockSizes on props change
    this.state = {blockSizes: {}};
  }

  render() {
    if (!this.props.func || !this.props.func.blocks)
      return <div />;

    const blocks = this.props.func.blocks;
    const gotAllSizes = _.every(
      blocks, block => this.state.blockSizes[block.address]);
    if (!gotAllSizes) {
      // render invisible blocks
      return (
        <div style={{opacity: 0}}>
          {_.map(blocks, block => (
            <div key={block.address}>
              <Measure
                bounds
                onResize={contentRect => {
                  this.setState({
                    blockSizes: update(
                      this.state.blockSizes,
                      {[block.address]: {$set: contentRect.bounds}}
                    ),
                  });
                }}
              >
                {({measureRef}) => (
                  <div ref={measureRef} style={{display: "inline-block"}}>
                    <BasicBlock block={block} />
                  </div>
                )}
              </Measure>
            </div>
          ))}
        </div>
      );
    }

    const g = new dagre.graphlib.Graph();
    g.setGraph({});
    g.setDefaultEdgeLabel(() => ({}));

    let blocksByAddress = {};

    for (let block of blocks) {
      const address = block.address;

      blocksByAddress[address] = block;

      // blockSizes actually also contains other stuff, let's not put it in the
      // node label
      const {width, height} = this.state.blockSizes[address];
      g.setNode(address, {width: width, height: height});
      for (let toAddr of block.flow) {
        g.setEdge(address, toAddr);
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
            const node = g.node(nodeID);
            const {x, y, width, height} = node;

            const block = blocksByAddress[nodeID];

            return (
              <g
                key={nodeID}
                transform={`translate(${x},${y})`}
              >
                <rect
                  width={width}
                  height={height}
                  fill="#4286f4"
                  stroke="black"
                  />

                <foreignObject width={width} height={height}>
                  <BasicBlock block={block} />
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
