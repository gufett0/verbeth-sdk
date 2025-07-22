import { http, createConfig } from 'wagmi';
import { base, mainnet, baseSepolia } from 'wagmi/chains';
import { connectorsForWallets } from '@rainbow-me/rainbowkit';
import {
  coinbaseWallet,
  metaMaskWallet,
  walletConnectWallet,
} from '@rainbow-me/rainbowkit/wallets';

const projectId = 'abcd4fa063dd349643afb0bdc85bb248';
const name       = 'Unstoppable Chat';


type CoinbaseParams = Parameters<typeof coinbaseWallet>[0];
const coinbaseEoa = (params: CoinbaseParams) => {
  const wallet = coinbaseWallet({ ...params, appName: name });
  (wallet as any).id         = 'coinbase';
  (wallet as any).preference = 'smartWallet';
  (wallet as any).meta       = { name: 'Coinbase Mobile / EOA' };
  return wallet;
};
const connectors = connectorsForWallets(
  [
    {
      groupName: 'Recommended',
      wallets: [coinbaseEoa],
    },
    {
      groupName: 'Other options',
      wallets: [walletConnectWallet, metaMaskWallet],
    },
  ],
  { appName: name, projectId }
);

export const config = createConfig({
  connectors,
  chains: [base, mainnet, baseSepolia],
  transports: {
    [mainnet.id]:    http(),
    [base.id]:       http('https://base-rpc.publicnode.com'),
    [baseSepolia.id]: http('https://base-sepolia-rpc.publicnode.com'),
  },
});