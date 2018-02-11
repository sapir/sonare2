import React, { Component } from 'react';
import { Message } from 'semantic-ui-react';


export default class ErrorMessage extends Component {
  constructor(props) {
    super(props);
    this.state = {visible: !!props.error};
  }

  componentWillReceiveProps(newProps) {
    if (newProps.error !== this.props.error) {
      this.setState({visible: !!newProps.error});
    }
  }

  onDismiss() {
    this.setState({visible: false});
  }

  render() {
    return (
      <Message
        compact
        floating
        error
        hidden={!this.state.visible}
        onDismiss={() => this.onDismiss()}
      >
        {this.props.error && (
          this.props.error.html
          ? <div dangerouslySetInnerHTML={{__html: this.props.error.html}} />
          : <div>{this.props.error.message}</div>
        )}
      </Message>
    );
  }
}
