"use client";

import React, { useEffect, useState } from "react";
import SetupWizard from "@/components/setup/SetupWizard";
import ConfigPage from "@/components/setup/ConfigPage";

export default function SetupPage() {
  const [onboarded, setOnboarded] = useState<boolean | null>(null);

  useEffect(() => {
    setOnboarded(localStorage.getItem("threatclaw_onboarded") === "true");
  }, []);

  if (onboarded === null) return null;

  if (!onboarded) {
    return (
      <div style={{ margin: "-0 -20px" }}>
        <SetupWizard />
      </div>
    );
  }

  return <ConfigPage onResetWizard={() => {
    localStorage.removeItem("threatclaw_onboarded");
    setOnboarded(false);
  }} />;
}
