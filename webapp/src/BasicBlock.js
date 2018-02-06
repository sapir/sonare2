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

  renderAsmLine(asmLine) {
    return (
      <div key={asmLine.start}>
        {_.map(asmLine.tokens, (token, i) => this.renderAsmToken(asmLine, token, i))}
      </div>
    );
  }

  render() {
    const block = this.props.block;

    return (
      <div key={block.address}>
        <h5>Block @ {block.address.toString(16)}</h5>
        {_.map(block.asmLines, asmLine => this.renderAsmLine(asmLine))}
      </div>
    );
  }
}
