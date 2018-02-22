import _ from 'lodash';
import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import { Sidebar, Segment, Header, List } from 'semantic-ui-react';
import { doApiQuery } from './api';
import ErrorMessage from './ErrorMessage';
import BlockGraph from './BlockGraph';
import './App.css';


class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      names: null,
      // TODO: just for debugging?
      error: null,
    };
  }

  componentWillMount() {
    this.reloadNames();
  }

  gotoFunc(funcName) {
    // TODO: escaping for slashes in names
    this.props.history.push(`/func/${funcName}`);
  }

  async doApiQuery(url, json, fetchArgs) {
    try {
      return await doApiQuery(url, json, fetchArgs);
    } catch (e) {
      this.setState({error: e});
      throw e;
    }
  }

  async reloadNames() {
    const names = await this.doApiQuery("/names");
    this.setState({names: names});

    if (names && this.props.location.pathname === "/") {
      // TODO: when we have a text view, maybe we want default to be sth else
      this.gotoFunc(names[0].name);
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

          <Sidebar.Pusher className="main-content">
            {/* TODO: only for debugging? */}
            <ErrorMessage error={this.state.error} />

            {this.props.match.params.funcName && (
              <BlockGraph funcName={this.props.match.params.funcName} />
            )}
          </Sidebar.Pusher>
        </Sidebar.Pushable>
      </div>
    );
  }
}

export default App;
