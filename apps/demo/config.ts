import { http, createConfig } from 'wagmi';
import { base, mainnet } from 'wagmi/chains';
import { connectorsForWallets } from '@rainbow-me/rainbowkit';
import {
  coinbaseWallet,
  metaMaskWallet,
  walletConnectWallet,
} from '@rainbow-me/rainbowkit/wallets';


const projectId = 'abcd4fa063dd349643afb0bdc85bb248';
const name       = 'Unstoppable Chat';



coinbaseWallet.preference = 'smartWalletOnly'; 
const connectors = connectorsForWallets(
  [
    {
      groupName: 'Recommended',
      wallets: [
        coinbaseWallet],
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
  chains: [base, mainnet],
  transports: {
    [mainnet.id]:    http(),
    [base.id]:       http('https://base-rpc.publicnode.com'),
  },
});