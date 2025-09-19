import ReactDOM from "react-dom/client";
import "./index.css";
import App from "./App";
import { RpcProvider } from "./rpc";
import { Providers } from "./providers";
import { Buffer } from "buffer";

if (!(window as any).Buffer) (window as any).Buffer = Buffer;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <RpcProvider>
    <Providers>
      <App />
    </Providers>
  </RpcProvider>
);