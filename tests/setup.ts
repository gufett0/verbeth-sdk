import { spawn, type ChildProcess } from "child_process";
import { JsonRpcProvider } from "ethers";

export class AnvilSetup {
  private process: ChildProcess | null = null;
  public provider: JsonRpcProvider;

  constructor(private port: number = 8545) {
    this.provider = new JsonRpcProvider(`http://localhost:${port}`);
  }

  async start(forkUrl: string, forkBlock?: number): Promise<void> {
    console.log("Starting Anvil (mainnet-fork)…");

    const params = [
      "--port",
      this.port.toString(),
      "--fork-url",
      forkUrl,
      "--chain-id",
      "8453",
      "--accounts",
      "10",
      "--balance",
      "1000",
      "--gas-limit",
      "30000000",
    ];

    if (forkBlock) {
      params.push("--fork-block-number", forkBlock.toString());
    }

    this.process = spawn("anvil", params);

    this.process.stdout?.on("data", (d) => process.stdout.write(`Anvil: ${d}`));
    this.process.stderr?.on("data", (d) =>
      process.stderr.write(`Anvil ❌ ${d}`)
    );

    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(
        () => reject(new Error("Anvil start timeout")),
        20_000
      );

      const ping = async () => {
        try {
          await this.provider.getBlockNumber();
          clearTimeout(t);
          console.log("Anvil ready (mainnet fork)!");
          resolve();
        } catch {
          setTimeout(ping, 300);
        }
      };
      ping();
    });
  }

  async stop(): Promise<void> {
    if (this.process) {
      console.log("Stopping Anvil…");
      this.process.kill();
      this.process = null;
    }
  }
}