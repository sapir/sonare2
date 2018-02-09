import _ from 'lodash';
import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import { Sidebar, Segment, Header, List } from 'semantic-ui-react';
import BlockGraph from './BlockGraph';
import './App.css';


class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      names: null,
      func: null,
    };

    const funcName = this.props.match.params.funcName;
    if (funcName) {
      this.loadGraph(funcName);
    }
  }

  componentWillMount() {
    this.reloadNames();
  }

  componentWillReceiveProps(props) {
    const oldFuncName = this.props.match.params.funcName;
    const newFuncName = props.match.params.funcName;
    if (newFuncName && newFuncName !== oldFuncName) {
      this.loadGraph(newFuncName);
    }
    if (!newFuncName) {
      this.setState({func: null});
    }
  }

  async reloadNames() {
    const response = await fetch("/api/names");
    const names = await response.json();
    this.setState({names: names});
    if (names) {
      // TODO: only redirect if no existing url, this is just a default
      // TODO: when we have a text view, maybe we want default to be sth else
      // TODO: escaping for slashes in names
      const newFuncName = names[0].name;
      this.props.history.push(`/func/${newFuncName}`);
    }
  }

  async loadGraph(funcName) {
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
  }

  render() {
    return (
      <div className="App">
        <Sidebar.Pushable as={Segment}>
          <Sidebar as={Segment} animation='push' width='wide' visible={true} icon='labeled' inverted vertical>
            <Header as="h3">Names</Header>
            <List>
              {_.map(this.state.names, name => (
                <List.Item key={name.name}>
                  {/* TODO: escaping etc. */}
                  <Link to={`/func/${name.name}`}>
                    {name.name}
                  </Link>
                </List.Item>
              ))}
            </List>
          </Sidebar>

          <Sidebar.Pusher>
            <Segment className="main-content" vertical>
              {this.state.func && <BlockGraph func={this.state.func} />}
            </Segment>
          </Sidebar.Pusher>
        </Sidebar.Pushable>
      </div>
    );
  }
}

export default App;
