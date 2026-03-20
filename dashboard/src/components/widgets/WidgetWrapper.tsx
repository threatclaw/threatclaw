"use client";

import React, { useState } from "react";
import { Settings, Pin, PinOff, X, Maximize2 } from "lucide-react";

interface WidgetWrapperProps {
  id: string;
  title: string;
  children: React.ReactNode;
  pinned?: boolean;
  onPin?: (id: string) => void;
  onRemove?: (id: string) => void;
  onExpand?: (id: string) => void;
  onConfigure?: (id: string) => void;
}

export default function WidgetWrapper({
  id,
  title,
  children,
  pinned = false,
  onPin,
  onRemove,
  onExpand,
  onConfigure,
}: WidgetWrapperProps) {
  const [showActions, setShowActions] = useState(false);

  return (
    <div
      className="pit"
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        position: "relative",
        overflow: "hidden",
      }}
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
    >
      {/* Header */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        marginBottom: "8px",
        minHeight: "20px",
      }}>
        <span className="label-caps">{title}</span>
        {showActions && (
          <div style={{ display: "flex", gap: "4px" }}>
            {onConfigure && (
              <button
                onClick={() => onConfigure(id)}
                className="btn-raised"
                style={{ padding: "3px 5px", fontSize: "0" }}
                title="Paramètres"
              >
                <Settings size={10} color="var(--text-secondary)" />
              </button>
            )}
            {onPin && (
              <button
                onClick={() => onPin(id)}
                className="btn-raised"
                style={{ padding: "3px 5px", fontSize: "0" }}
                title={pinned ? "Désépingler du menu" : "Épingler au menu"}
              >
                {pinned ? (
                  <PinOff size={10} color="var(--accent-danger)" />
                ) : (
                  <Pin size={10} color="var(--text-secondary)" />
                )}
              </button>
            )}
            {onExpand && (
              <button
                onClick={() => onExpand(id)}
                className="btn-raised"
                style={{ padding: "3px 5px", fontSize: "0" }}
                title="Page complète"
              >
                <Maximize2 size={10} color="var(--text-secondary)" />
              </button>
            )}
            {onRemove && (
              <button
                onClick={() => onRemove(id)}
                className="btn-raised"
                style={{ padding: "3px 5px", fontSize: "0" }}
                title="Retirer du dashboard"
              >
                <X size={10} color="var(--text-muted)" />
              </button>
            )}
          </div>
        )}
      </div>

      {/* Content */}
      <div style={{ flex: 1, minHeight: 0 }}>
        {children}
      </div>
    </div>
  );
}
