import _ from 'lodash';
import React, { Component } from 'react';


export default class BasicBlock extends Component {
  renderAsmToken(asmLine, token, i) {
    let className = `token-${token.type}`;

    if (token.type === "operand") {
      const op = asmLine.operands[token.index];
      className += ` token-operand-${op.type}`;

      if (token.part_type !== "full") {
        className += ` token-operand-${op.type}-${token.part_type}`;
      }
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

    return (
      <tr key={asmLine.start}>
        <td>
          {this.renderAsmTokens(asmLine, mnemonicTokens)}
          {/*
            pad mnemonics column with non-breaking spaces.
            of course, table column will be aligned visually anyway, but this
            way, a. the columns are separately by exactly one space, and b.
            if the user tries to copy the text to their clipboard, they get
            it nicely formatted.
            TODO: I tested this and I got double spaces in the clipboard text
          */}
          {_.repeat("\u00a0", maxMnemonicLength + 1 - mnemonicLength)}
        </td>
        <td>{this.renderAsmTokens(asmLine, rest)}</td>
      </tr>
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
        <table>
          <tbody>
            {_.map(
              block.asmLines,
              asmLine => this.renderAsmLine(asmLine, maxMnemonicLength)
            )}
          </tbody>
        </table>
      </div>
    );
  }
}