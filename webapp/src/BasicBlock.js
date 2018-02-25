import _ from 'lodash';
import React, { Component } from 'react';
import { Link } from 'react-router-dom';
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
    let string = token.string;
    let className = `token-${token.type}`;

    if (token.type === "operand") {
      const op = asmLine.operands[token.index];
      className += ` token-operand-${op.type}`;

      className += ` token-operand-${token.part_type}`;

      if (op.ref) {
        const refValue = (op.value !== undefined) ? op.value : op.imm;
        if (refValue !== undefined) {
          if (token.part_idx > 0) {
            // we replaced the first part with a different string (in the else
            // clause of this "if" for a previous token) so now clear the other
            // parts
            return null;
          } else {
            const name = (this.props.namesByAddress || {})[refValue];
            string = name || refValue.toString(16);

            // TODO: "&& name" is only because API doesn't know how to get
            // funcs by address yet. fix that then fix this.
            // TODO: links to code that isn't a function start.
            if (op.ref.dtype === "func" && name) {
              return (
                <Link
                  key={i}
                  className={className}
                  to={`/func/${name}`}
                >
                  {string}
                </Link>
              );
            }
          }
        }
      }
    }

    return (
      <span key={i} className={className}>
        {string}
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
    if (asmLine.elided)
      return null;

    const tokens = asmLine.tokens;
    const mnemonicTokens = this.getMnemonicTokens(asmLine);
    const rest = _.drop(tokens, mnemonicTokens.length);

    const mnemonicLength = this.getTokensLength(mnemonicTokens);

    const localEdits = this.state.localEdits[asmLine.start] || {};

    const lines = [];

    const name = (
      (localEdits.name !== undefined ? localEdits.name : asmLine.name)
      || (isFirstInBlock ? `loc_${asmLine.start.toString(16)}` : null)
    );

    function addPreLabelLine() {
      // add an empty line
      // TODO: don't include this in tabIndex etc.
      if (!isFirstInBlock)
        lines.push(<div key="prelabel">&nbsp;</div>);
    }

    if (this.isEditing("name", asmLine)) {
      addPreLabelLine();

      /* TODO: display ":" after input during editing, but don't save it and
      don't let user select it or delete it */
      lines.push(
        <div key="label" className="label input-line">
          <input
              type="text"
              ref={this.onInputRef}
              defaultValue={name}
              onKeyDown={this.onInputKeyDown}
              onBlur={this.saveEdit}
              />
        </div>
      );
    } else if (name) {
      addPreLabelLine();

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
        <span className="address">
          {_.padStart(asmLine.start.toString(16), 8, "\u00a0")}
        </span>
        {_.repeat("\u00a0", 2)}
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

    case "n":
      this.setState({editAddr: asmLine.start, editField: "name"});
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
    let {value} = event.target;

    // set to null when empty because otherwise we get DB conflicts for the
    // line named "" (on clearing names).

    // TODO: user_lines table overrides everything else, so although clearing
    // the name might mean "don't override the default", it might really mean
    // "don't use the default, clear the name completely". it seems we're doing
    // the former, maybe we should be doing the latter.

    if (!value)
      value = null;

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

    case "name":
      await doApiQuery(
        "/set_line_name",
        {
          addr: editAddr,
          name: value,
        });
      break;

    default:
      throw new Error(
        `Don't know how to save edit for {editAddr.toString(16)}:{editField}`);
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
      <div
        key={block.address}
        className="block"
        onMouseDown={this.props.onMouseDown}
      >
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
