import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource-variable/instrument-sans";
import App from "./App";
import "./index.css";
import { applyTheme, detectThemePref } from "./theme";
import { detectLocale } from "./i18n";

applyTheme(detectThemePref());
document.documentElement.lang = detectLocale();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
