import _ from 'lodash';
import React, { Component } from 'react';
import { Sidebar, Segment, Header, List } from 'semantic-ui-react';
import './App.css';

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      names: null,
      func: null,
    };
  }

  componentWillMount() {
    this.reloadNames();
  }

  async reloadNames() {
    const response = await fetch("/api/names");
    const names = await response.json();
    this.setState({names: names});
    if (names) {
      this.loadGraph(names[0].name);
    }
  }

  async loadGraph(funcName) {
    const response = await fetch(`/api/func/${funcName}`);
    const json = await response.json();
    this.setState({func: json});
  }

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
        <h5>Block @ {block.address.toString(16)} -> [{
          _.map(block.flow, (nextBlock, i) =>
            <span key={i}>
              {i > 0 ? ", " : null}
              {nextBlock.toString(16)}
            </span>
        )}]</h5>
        {_.map(asmLines, asmLine => this.renderAsmLine(asmLine))}
      </div>
    );
  }

  render() {
    const asmLinesByAddress = _.fromPairs(
      _.map(
        this.state.func ? this.state.func.asm_lines : [],
        asmLine => [asmLine.start, asmLine]));

    return (
      <div className="App">
        <Sidebar.Pushable as={Segment}>
          <Sidebar as={Segment} animation='push' width='wide' visible={true} icon='labeled' inverted vertical>
            <Header as="h3">Names</Header>
            <List>
              {_.map(this.state.names, name => (
                <List.Item key={name.name}>
                  {name.name}
                </List.Item>
              ))}
            </List>
          </Sidebar>

          <Sidebar.Pusher>
            <Segment className="main-content" vertical>
              {this.state.func && (
                _.map(this.state.func.blocks, block =>
                  this.renderBlock(block, asmLinesByAddress))
              )}
            </Segment>
          </Sidebar.Pusher>
        </Sidebar.Pushable>
      </div>
    );
  }
}

export default App;
