import ReactDOM from "react-dom/client";
import "./index.css";
import App from "./App";
import { HeliosProvider } from "./helios";
import { Providers } from "./providers";
import { Buffer } from "buffer";

// Required for some dependencies
if (!(window as any).Buffer) (window as any).Buffer = Buffer;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <HeliosProvider>
    <Providers>
      <App />
    </Providers>
  </HeliosProvider>
);