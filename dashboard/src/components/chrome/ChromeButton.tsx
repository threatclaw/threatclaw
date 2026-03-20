"use client";

import React from "react";
import styles from "./chrome-button.module.css";

interface ChromeButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
}

export function ChromeButton({ children, onClick, disabled, className = "" }: ChromeButtonProps) {
  return (
    <button
      className={`${styles.button} ${styles.rect} ${className}`}
      onClick={onClick}
      disabled={disabled}
    >
      <div className={styles.buttonOuter}>
        <div className={styles.buttonInner}>
          <span>{children}</span>
        </div>
      </div>
    </button>
  );
}
