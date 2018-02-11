import _ from 'lodash';
import React, { Component } from 'react';
import update from 'immutability-helper';
import dagre from 'dagre';
import Measure from 'react-measure';
import BasicBlock from './BasicBlock';


export default class BlockGraph extends Component {
  constructor(props) {
    super(props);

    // TODO: clear blockSizes on function change
    this.state = {
      func: null,
      blockSizes: {},
    };

    if (props.funcName) {
      this.loadFunc(props.funcName);
    }
  }

  componentWillReceiveProps(newProps) {
    const oldFuncName = this.props.funcName;
    const newFuncName = newProps.funcName;
    if (newFuncName && newFuncName !== oldFuncName) {
      this.loadFunc(newFuncName);
    }
    if (!newFuncName) {
      this.setState({func: null});
    }
  }

  async loadFunc(funcName) {
    try {
      const response = await fetch(`/api/func/${funcName}`);
      const func = await response.json();

      // fill in block asmLines
      const asmLinesByAddress = _.fromPairs(
        _.map(
          func ? func.asm_lines : [],
          asmLine => [asmLine.start, asmLine]));

      for (let block of func.blocks) {
        // TODO: handle asmLines missing from asmLinesByAddress
        block.asmLines = _.map(block.opcodes, addr => asmLinesByAddress[addr]);
      }

      this.setState({func: func});
    } catch (e) {
      this.setState({func: null});
      throw e;
    }
  }

  makeBlockGraph(blocks) {
    const g = new dagre.graphlib.Graph();
    g.setGraph({});
    g.setDefaultEdgeLabel(() => ({}));

    for (let block of blocks) {
      const address = block.address;

      // blockSizes actually also contains other stuff, let's not put it in the
      // node label
      const {width, height} = this.state.blockSizes[address];
      g.setNode(address, {width: width, height: height});

      for (let toAddr of block.flow) {
        g.setEdge(address, toAddr);
      }
    }

    return g;
  }

  layoutBlockGraph(g) {
    dagre.layout(g);

    const nodes = g.nodes();
    const nodeLabels = _.map(nodes, nodeID => g.node(nodeID));

    for (let n of nodeLabels) {
      n.left = n.x - n.width / 2;
      n.top = n.y - n.height / 2;
    }
  }

  render() {
    if (!this.state.func || !this.state.func.blocks)
      return <div />;

    const blocks = this.state.func.blocks;
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

    let blocksByAddress = _.fromPairs(
      _.map(blocks, block => [block.address, block]));

    const g = this.makeBlockGraph(blocks);
    this.layoutBlockGraph(g);

    const nodes = g.nodes();
    const nodeLabels = _.map(nodes, nodeID => g.node(nodeID));

    const graphWidth = _.max(_.map(nodeLabels, n => n.left + n.width));
    const graphHeight = _.max(_.map(nodeLabels, n => n.top + n.height));

    return (
      <svg width={graphWidth} height={graphHeight} className="block-graph">
        <rect width="100%" height="100%" className="background" />

        <marker
          id="arrow"
          markerWidth={10}
          markerHeight={9}
          refX={10}
          refY={4.5}
          markerUnits="strokeWidth"
          orient="auto"
        >
          <path d="M0,0 L0,9 L10,4.5 Z" />
        </marker>

        <g>
          {_.map(nodes, nodeID => {
            const node = g.node(nodeID);
            const {left, top, width, height} = node;

            const block = blocksByAddress[nodeID];

            return (
              <g
                key={nodeID}
                transform={`translate(${left},${top})`}
              >
                <rect
                  width={width}
                  height={height}
                  className="block"
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

            return (
              <line
                key={[v, w]}
                x1={nodeA.x} y1={nodeA.top + nodeA.height + 2}
                x2={nodeB.x} y2={nodeB.top - 2}
                strokeWidth={2} stroke="black"
                markerEnd="url(#arrow)"
                />
            );
          })}
        </g>
      </svg>
    );
  }
}
