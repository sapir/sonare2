import _ from 'lodash';
import React, { Component } from 'react';
import { Sidebar, Segment, Header, List } from 'semantic-ui-react';
import './App.css';

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      names: null,
    };
  }

  componentWillMount() {
    this.reloadNames();
  }

  async reloadNames() {
    const response = await fetch("/api/names");
    const json = await response.json();
    this.setState({names: json});
  }

  render() {
    return (
      <div className="App">
        <Sidebar.Pushable as={Segment}>
          <Sidebar as={Segment} animation='push' width='thin' visible={true} icon='labeled' inverted vertical>
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
              disassembly goes here
            </Segment>
          </Sidebar.Pusher>
        </Sidebar.Pushable>
      </div>
    );
  }
}

export default App;
