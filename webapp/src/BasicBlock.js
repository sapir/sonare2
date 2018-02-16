import _ from 'lodash';
import React, { Component } from 'react';
import update from 'immutability-helper';
import { doApiQuery } from './api';


export default class BasicBlock extends Component {
  constructor(props) {
    super(props);

    this.onInputRef = this.onInputRef.bind(this);
    this.onInputKeyDown = this.onInputKeyDown.bind(this);
    this.saveEdit = this.saveEdit.bind(this);

    this.state = {
      editAddr: null,
      editField: null,
      localEdits: {},
    }
  }

  renderAsmToken(asmLine, token, i) {
    let className = `token-${token.type}`;

    if (token.type === "operand") {
      const op = asmLine.operands[token.index];
      className += ` token-operand-${op.type}`;

      className += ` token-operand-${token.part_type}`;
    }

    return (
      <span key={i} className={className}>
        {token.string}
      </span>
    );
  }

  renderAsmTokens(asmLine, tokens) {
    return _.map(tokens, (token, i) => this.renderAsmToken(asmLine, token, i));
  }

  getMnemonicTokens(asmLine) {
    return _.takeWhile(
      asmLine.tokens, token => token.type.startsWith("mnemonic"));
  }

  getTokensLength(tokens) {
    return _.sumBy(tokens, t => t.string.length);
  }

  isEditing(editField, asmLine) {
    return (this.state
            && this.state.editAddr === asmLine.start
            && this.state.editField === editField);
  }

  renderAsmLine(asmLine, maxMnemonicLength, isFirstInBlock) {
    const tokens = asmLine.tokens;
    const mnemonicTokens = this.getMnemonicTokens(asmLine);
    const rest = _.drop(tokens, mnemonicTokens.length);

    const mnemonicLength = this.getTokensLength(mnemonicTokens);

    const localEdits = this.state.localEdits[asmLine.start] || {};

    const lines = [];

    const name = (
      asmLine.name ? asmLine.name
      : isFirstInBlock ? `loc_${asmLine.start.toString(16)}`
      : null
    );

    if (name) {
      // add an empty line
      // TODO: don't include this in tabIndex etc.
      if (!isFirstInBlock)
        lines.push(<div key="prelabel">&nbsp;</div>);

      // TODO: label should be a bit to the left of the code
      lines.push(
        <div key="label" className="label">
          {name}:
        </div>
      );
    }

    // prefer local copy
    const comment = (
      (localEdits.comment !== undefined)
      ? localEdits.comment
      : asmLine.comment
    );

    if (this.isEditing("comment", asmLine)) {
      lines.push(
        <div key="comment" className="comment input-line">
          ;&nbsp;<input
              type="text"
              ref={this.onInputRef}
              defaultValue={comment}
              onKeyDown={this.onInputKeyDown}
              onBlur={this.saveEdit}
              />
        </div>
      );
    } else if (comment) {
      lines.push(
        <div key="comment" className="comment">
          ; {comment}
        </div>
      );
    }

    lines.push(
      <div key="asm">
        {this.renderAsmTokens(asmLine, mnemonicTokens)}
        {/*
          pad mnemonics to max width, with non-breaking spaces.
          note that "rest" already includes a space token after the mnemonic,
          so there'll be a space before any operands etc.
        */}
        {_.repeat("\u00a0", maxMnemonicLength - mnemonicLength)}
        {this.renderAsmTokens(asmLine, rest)}
      </div>
    );

    return (
      <div
        key={asmLine.start}
        tabIndex={0}
        onKeyPress={(event) => this.onAsmLineKeyPress(asmLine, event)}
        className="asm-line"
      >
        {lines}
      </div>
    );
  }

  onAsmLineKeyPress(asmLine, event) {
    if (this.state.editField) {
      // already editing, let text <input> handle key presses
      return;
    }

    switch (event.key) {
    case ";":
      this.setState({editAddr: asmLine.start, editField: "comment"});
      event.preventDefault();
      break;

    default: break;
    }
  }

  onInputRef(input) {
    if (input) {
      input.focus();
      input.select();
    }
  }

  onInputKeyDown(event) {
    if (event.key === "Enter") {
      this.saveEdit(event);
      event.preventDefault();
      // TODO: focus assembly line
    }
  }

  // called by <input> events
  saveEdit(event) {
    // TODO: push to server. clear localEdits on server reply.
    const {editAddr, editField} = this.state;
    const {value} = event.target;

    this.setState({
      editAddr: null,
      editField: null,
      localEdits: update(
        this.state.localEdits,
        {
          [editAddr]: edits =>
            update(edits || {}, {
              [editField]: {
                $set: value
              }
            })
        }),
    });

    this.uploadEdit(editAddr, editField, value);

    event.preventDefault();
  }

  async uploadEdit(editAddr, editField, value) {
    // TODO: on error...? do what?
    switch (editField) {
    case "comment":
      await doApiQuery(
        "/set_line_comment",
        {
          addr: editAddr,
          comment: value,
        });
      break;

    default: break;
    }
  }

  render() {
    const block = this.props.block;

    const maxMnemonicLength = _.max(
      _.map(
        block.asmLines,
        asmLine => this.getTokensLength(this.getMnemonicTokens(asmLine))
      )
    );

    return (
      <div key={block.address} className="block">
        {_.map(
          block.asmLines,
          (asmLine, i) => (
            this.renderAsmLine(asmLine, maxMnemonicLength, (i === 0))
          )
        )}
      </div>
    );
  }
}
