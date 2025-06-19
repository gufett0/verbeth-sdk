import { http, createConfig } from 'wagmi'
import { base, mainnet, baseSepolia } from 'wagmi/chains'
import { connectorsForWallets } from '@rainbow-me/rainbowkit'
import {
  argentWallet,
  braveWallet,
  coinbaseWallet,
  injectedWallet,
  ledgerWallet,
  metaMaskWallet,
  okxWallet,
  phantomWallet,
  rabbyWallet,
  rainbowWallet,
  safeWallet,
  trustWallet,
  uniswapWallet,
  walletConnectWallet,
  xdefiWallet,
  zerionWallet,
} from '@rainbow-me/rainbowkit/wallets'

const projectId = 'abcd4fa063dd349643afb0bdc85bb248';

const connectors = connectorsForWallets(
  [
    {
      groupName: 'Recommended',
      wallets: [
        metaMaskWallet,
        coinbaseWallet,
        rainbowWallet,
        walletConnectWallet,
      ],
    },
    {
      groupName: 'Popular',
      wallets: [
        trustWallet,
        ledgerWallet,
        braveWallet,
        uniswapWallet,
        phantomWallet,
      ],
    },
    {
      groupName: 'More Options',
      wallets: [
        argentWallet,
        rabbyWallet,
        okxWallet,
        xdefiWallet,
        zerionWallet,
        safeWallet,
        injectedWallet,
      ],
    },
  ],
  {
    appName: 'Helios × VerbEth Demo',
    projectId,
  }
)

export const config = createConfig({
  connectors,
  chains: [base, mainnet, baseSepolia],
  transports: {
    [mainnet.id]: http(),
    [base.id]: http('https://base-rpc.publicnode.com'),
    [baseSepolia.id]: http('https://base-sepolia-rpc.publicnode.com'),
  },
})