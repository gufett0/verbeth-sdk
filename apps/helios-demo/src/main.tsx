import ReactDOM from "react-dom/client";
import "./index.css";
import App from "./App";
import { HeliosProvider } from "./helios";
import { Buffer } from "buffer";
if (!(window as any).Buffer) (window as any).Buffer = Buffer;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <HeliosProvider>
    <App />
  </HeliosProvider>
);
