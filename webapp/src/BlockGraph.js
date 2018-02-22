import _ from 'lodash';
import React, { Component } from 'react';
import update from 'immutability-helper';
import dagre from 'dagre';
import { AutoSizer } from 'react-virtualized'
import Measure from 'react-measure';
import DragScroll from 'react-dragscroll';
import { doApiQuery } from './api';
import ErrorMessage from './ErrorMessage';
import BasicBlock from './BasicBlock';


export default class BlockGraph extends Component {
  constructor(props) {
    super(props);

    this.onBlockMouseDown = this.onBlockMouseDown.bind(this);

    // TODO: clear blockSizes on function change
    this.state = {
      error: null,
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
      const func = await doApiQuery(`/func/${funcName}`);

      // fill in block asmLines
      const asmLinesByAddress = _.fromPairs(
        _.map(
          func ? func.asm_lines : [],
          asmLine => [asmLine.start, asmLine]));

      const namesByAddress = {};

      // merge names and user_lines into asm_lines. user_lines has precedence.
      // similary, save names in namesByAddress, with precedence for
      // user_lines.
      if (func) {
        for (let nameObj of func.names) {
          namesByAddress[nameObj.start] = nameObj.name;

          const asmLine = asmLinesByAddress[nameObj.start];
          if (asmLine) {
            asmLine.name = nameObj.name;
          }
        }

        // TODO: handle userLines that don't match asmLine start addresses
        for (let userLine of func.user_lines) {
          _.merge(asmLinesByAddress[userLine.start], userLine);

          if (userLine.name) {
            namesByAddress[userLine.start] = userLine.name;
          }
        }
      }

      for (let block of func.blocks) {
        // TODO: handle asmLines missing from asmLinesByAddress
        block.asmLines = _.map(block.opcodes, addr => asmLinesByAddress[addr]);
      }

      this.setState({
        error: null,
        func: func,
        blockSizes: {},
        namesByAddress: namesByAddress,
      });

    } catch (e) {
      this.setState({
        error: e,
        func: null,
        blockSizes: {},
        namesByAddress: null,
      });

      throw e;
    }
  }

  onBlockMouseDown(event) {
    // prevent dragging when trying to select text
    event.stopPropagation();
  }

  makeBlockGraph(blocks) {
    const g = new dagre.graphlib.Graph();
    g.setGraph({});
    g.setDefaultEdgeLabel(() => ({}));

    for (let block of blocks) {
      const address = block.address;

      const label = {};

      const blockSize = this.state.blockSizes[address];
      if (blockSize) {
        // blockSizes actually also contains other stuff, let's not put it in
        // the node label. filter it out.
        label.width = blockSize.width;
        label.height = blockSize.height;
      }

      g.setNode(address, label);

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

  nodeHasLayout(label) {
    return (
        label.left !== undefined
        && label.top !== undefined
        && label.width !== undefined
        && label.height !== undefined
    );
  }

  renderSvgBlock(block, node) {
    const {left, top} = node;

    let sizeProps = (
      this.nodeHasLayout(node)
      ? {width: node.width, height: node.height}
      // if we don't have a layout, just use a really big maximum number
      // so that BasicBlock component isn't constrained
      : {width: 20000, height: 20000}
    );

    return (
      <g
        key={block.address}
        transform={
          this.nodeHasLayout(node)
          ? `translate(${left},${top})`
          : null
        }
      >
        <rect className="block" {...sizeProps} />

        <foreignObject {...sizeProps}>
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
                <BasicBlock
                  block={block}
                  namesByAddress={this.state.namesByAddress}
                  onMouseDown={this.onBlockMouseDown}
                  />
              </div>
            )}
          </Measure>
        </foreignObject>
      </g>
    );
  }

  renderSvg() {
    if (!this.state.func || !this.state.func.blocks) {
      return null;
    }

    const blocks = this.state.func.blocks;
    const gotAllSizes = _.every(
      blocks, block => this.state.blockSizes[block.address]);

    const blocksByAddress = _.fromPairs(
      _.map(blocks, block => [block.address, block]));

    const g = this.makeBlockGraph(blocks);
    const nodes = g.nodes();

    const svgProps = {};
    if (gotAllSizes) {
      this.layoutBlockGraph(g);

      const nodeLabels = _.map(nodes, nodeID => g.node(nodeID));

      svgProps.width = _.max(_.map(nodeLabels, n => n.left + n.width));
      svgProps.height = _.max(_.map(nodeLabels, n => n.top + n.height));
    }

    return (
      <AutoSizer>
        {({width, height}) => (
          <DragScroll width={width} height={height}>
            <svg className="block-graph" {...svgProps}>
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

              <g style={gotAllSizes ? null : {opacity: 0}}>
                {_.map(nodes, nodeID => {
                  const node = g.node(nodeID);
                  const block = blocksByAddress[nodeID];
                  return this.renderSvgBlock(block, node);
                })}

                {_.map(g.edges(), ({v, w}) => {
                  let nodeA = g.node(v);
                  let nodeB = g.node(w);
                  if (!this.nodeHasLayout(nodeA) || !this.nodeHasLayout(nodeB))
                    return null;

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
          </DragScroll>
        )}
      </AutoSizer>
    );
  }

  render() {
    return (
      <div style={{height: "100%"}}>
        <ErrorMessage error={this.state.error} />
        {this.renderSvg()}
      </div>
    );
  }
}
