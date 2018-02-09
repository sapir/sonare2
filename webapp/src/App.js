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
      // TODO: just for debugging?
      error: null,
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

  async doApiQuery(url, ...fetchArgs) {
    let response;

    try {
      response = await fetch(`/api/${url}`);
    } catch (error) {
      this.setState({error: `error accessing API`});
      throw error;
    }

    if (!response.ok) {
      this.setState({error: await response.text()});
      throw new Error(`got http error: ${response.statusText}`);
    }

    let data;

    try {
      data = await response.json();
    } catch (error) {
      this.setState({error: `error parsing JSON`});
      throw error;
    }

    this.setState({error: null});

    return data;
  }

  async reloadNames() {
    const names = await this.doApiQuery("/names");
    this.setState({names: names});

    if (names && this.props.location.pathname === "/") {
      // TODO: when we have a text view, maybe we want default to be sth else
      // TODO: escaping for slashes in names
      const newFuncName = names[0].name;
      this.props.history.push(`/func/${newFuncName}`);
    }
  }

  async loadGraph(funcName) {
    try {
      const func = await this.doApiQuery(`/func/${funcName}`);

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
    } catch (error) {
      this.setState({func: null});
      throw error;
    }
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
              {/* TODO: only for debugging? */}
              {this.state.error && (
                <div dangerouslySetInnerHTML={{__html: this.state.error}} />
              )}
              {this.state.func && <BlockGraph func={this.state.func} />}
            </Segment>
          </Sidebar.Pusher>
        </Sidebar.Pushable>
      </div>
    );
  }
}

export default App;
