import _ from 'lodash';
import React, { Component } from 'react';


export default class BasicBlock extends Component {
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

  renderAsmLine(asmLine, maxMnemonicLength) {
    const tokens = asmLine.tokens;
    const mnemonicTokens = this.getMnemonicTokens(asmLine);
    const rest = _.drop(tokens, mnemonicTokens.length);

    const mnemonicLength = this.getTokensLength(mnemonicTokens);

    const lines = [];

    if (asmLine.name) {
      // add an empty line
      // TODO: not for first line in block
      lines.push(<div key="prelabel" />);

      // TODO: label should be a bit to the left of the code
      lines.push(
        <div key="label" className="label">
          {asmLine.name}:
        </div>
      );
    }

    if (asmLine.comment) {
      lines.push(
        <div key="comment" className="comment">
          ; {asmLine.comment}
        </div>
      );
    }

    lines.push(
      <div key="asm">
        {this.renderAsmTokens(asmLine, mnemonicTokens)}
        {/*
          pad mnemonics to column width, with non-breaking spaces.
          TODO: I tested copying to clipboard and I got an extra space in the
          clipboard text
        */}
        {_.repeat("\u00a0", maxMnemonicLength + 1 - mnemonicLength)}
        {this.renderAsmTokens(asmLine, rest)}
      </div>
    );

    return (
      <div key={asmLine.start}>
        {lines}
      </div>
    );
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
        <h5>0x{block.address.toString(16)}:</h5>
        {_.map(
          block.asmLines,
          asmLine => this.renderAsmLine(asmLine, maxMnemonicLength)
        )}
      </div>
    );
  }
}
