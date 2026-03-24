"use client";

import React from "react";

interface Props {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

export default function EmbossedButton({ children, onClick, disabled, className, style }: Props) {
  return (
    <button className={`tc-btn-embossed ${className || ""}`} onClick={onClick} disabled={disabled} style={style}>
      <div className="tc-btn-outer">
        <div className="tc-btn-inner">
          <span>{children}</span>
        </div>
      </div>
    </button>
  );
}
