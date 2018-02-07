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

  renderAsmLine(asmLine) {
    const tokens = asmLine.tokens;
    const mnemonicTokens = _.takeWhile(
      tokens, token => token.type.startsWith("mnemonic"));
    const rest = _.drop(tokens, mnemonicTokens.length);

    return (
      <tr key={asmLine.start}>
        <td>{this.renderAsmTokens(asmLine, mnemonicTokens)}</td>
        <td>{this.renderAsmTokens(asmLine, rest)}</td>
      </tr>
    );
  }

  render() {
    const block = this.props.block;

    return (
      <div key={block.address} className="block">
        <h5>0x{block.address.toString(16)}:</h5>
        <table>
          <tbody>
            {_.map(block.asmLines, asmLine => this.renderAsmLine(asmLine))}
          </tbody>
        </table>
      </div>
    );
  }
}
