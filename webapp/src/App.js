import React, { Component } from 'react';
import { Sidebar, Segment, Header, List } from 'semantic-ui-react';
import './App.css';

class App extends Component {
  render() {
    return (
      <div className="App">
        <Sidebar.Pushable as={Segment}>
          <Sidebar as={Segment} animation='push' width='thin' visible={true} icon='labeled' inverted vertical>
            <Header as="h3">Names</Header>
            <List>
              <List.Item>main</List.Item>
              <List.Item>func1</List.Item>
              <List.Item>func2</List.Item>
            </List>
          </Sidebar>

          <Sidebar.Pusher>
            <Segment basic>
              disassembly goes here
            </Segment>
          </Sidebar.Pusher>
        </Sidebar.Pushable>
      </div>
    );
  }
}

export default App;
