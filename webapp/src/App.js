import _ from 'lodash';
import React, { Component } from 'react';
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
                  {name.name}
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
