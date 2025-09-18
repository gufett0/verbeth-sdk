import { useCallback } from "react";
import nacl from "tweetnacl";
import {
  sendEncryptedMessage,
  initiateHandshake,
  respondToHandshake,
  IExecutor,
  IdentityKeyPair,
  IdentityProof,
  getNextNonce,
} from "@verbeth/sdk";
import {
  Contact,
  generateConversationTopic,
  generateTempMessageId,
} from "../types.js";
import { VoidSigner } from "ethers";

interface UseChatActionsProps {
  address: `0x${string}` | undefined;
  baseAddress: string | null;
  baseProvider: any;
  signer: any;
  executor: IExecutor | null;
  identityKeyPair: IdentityKeyPair | null;
  identityProof: IdentityProof | null;
  addLog: (message: string) => void;
  updateContact: (contact: Contact) => Promise<void>;
  addMessage: (message: any) => Promise<void>;
  removePendingHandshake: (id: string) => Promise<void>;
  setSelectedContact: (contact: Contact | null) => void;
  setLoading: (loading: boolean) => void;
  setMessage: (message: string) => void;
  setRecipientAddress: (address: string) => void;
}

export const useChatActions = ({
  address,
  baseAddress,
  baseProvider,
  signer,
  executor,
  identityKeyPair,
  identityProof,
  addLog,
  updateContact,
  addMessage,
  removePendingHandshake,
  setSelectedContact,
  setLoading,
  setMessage,
  setRecipientAddress,
}: UseChatActionsProps) => {
  const getCurrentSigner = useCallback(() => {
    if (signer) return signer;
    if (baseProvider && baseAddress) {
      return new VoidSigner(baseAddress, baseProvider);
    }
    return null;
  }, [signer, baseProvider, baseAddress]);

  const sendHandshake = useCallback(
    async (recipientAddress: string, message: string) => {
      const currentAddress = address || baseAddress;
      const currentSigner = getCurrentSigner();

      if (
        !executor ||
        !currentAddress ||
        !recipientAddress ||
        !message ||
        !identityKeyPair ||
        !identityProof ||
        !currentSigner
      ) {
        addLog("✗ Missing required data for handshake");
        return;
      }

      setLoading(true);
      try {
        const ephemeralKeyPair = nacl.box.keyPair();

        const tx = await initiateHandshake({
          executor,
          recipientAddress,
          identityKeyPair,
          ephemeralPubKey: ephemeralKeyPair.publicKey,
          plaintextPayload: message,
          identityProof,
          signer: currentSigner,
        });

        const newContact: Contact = {
          address: recipientAddress,
          ownerAddress: currentAddress,
          status: "handshake_sent",
          ephemeralKey: ephemeralKeyPair.secretKey,
          topic: tx.hash,
          lastMessage: message,
          lastTimestamp: Date.now(),
        };

        await updateContact(newContact);
        setSelectedContact(newContact);

        const handshakeMessage = {
          id: generateTempMessageId(),
          topic: generateConversationTopic(currentAddress, recipientAddress),
          sender: currentAddress,
          recipient: recipientAddress,
          ciphertext: "",
          timestamp: Date.now(),
          blockTimestamp: Date.now(),
          blockNumber: 0,
          direction: "outgoing" as const,
          decrypted: `Request: "${message}"`,
          read: true,
          nonce: 0,
          dedupKey: `handshake-${tx.hash}`,
          type: "system" as const,
          ownerAddress: currentAddress,
          status: "pending" as const,
        };

        await addMessage(handshakeMessage);

        addLog(
          `Handshake sent to ${recipientAddress.slice(
            0,
            8
          )}...: "${message}" (tx: ${tx.hash})`
        );
        setMessage("");
        setRecipientAddress("");
      } catch (error) {
        console.error("Failed to send handshake:", error);
        addLog(
          `✗ Failed to send handshake: ${
            error instanceof Error ? error.message : "Unknown error"
          }`
        );
      } finally {
        setLoading(false);
      }
    },
    [
      address,
      baseAddress,
      executor,
      identityKeyPair,
      identityProof,
      getCurrentSigner,
      addLog,
      updateContact,
      addMessage,
      setSelectedContact,
      setLoading,
      setMessage,
      setRecipientAddress,
    ]
  );

  const acceptHandshake = useCallback(
    async (handshake: any, responseMessage: string) => {
      const currentAddress = address || baseAddress;
      const currentSigner = getCurrentSigner();

      if (
        !executor ||
        !currentAddress ||
        !identityKeyPair ||
        !identityProof ||
        !currentSigner
      ) {
        addLog("✗ Missing required data for handshake response");
        return;
      }

      try {
        const tx = await respondToHandshake({
          executor,
          inResponseTo: handshake.id,
          initiatorPubKey: handshake.ephemeralPubKey,
          responderIdentityKeyPair: identityKeyPair,
          note: responseMessage,
          identityProof,
          signer: currentSigner,
        });

        const newContact: Contact = {
          address: handshake.sender,
          ownerAddress: currentAddress,
          status: "established",
          identityPubKey: handshake.identityPubKey,
          signingPubKey: handshake.signingPubKey,
          lastMessage: responseMessage,
          lastTimestamp: Date.now(),
        };

        await updateContact(newContact);
        await removePendingHandshake(handshake.id);
        setSelectedContact(newContact);

        const conversationTopic = generateConversationTopic(
          currentAddress,
          handshake.sender
        );
        const acceptanceMessage = {
          id: generateTempMessageId(),
          topic: conversationTopic,
          sender: currentAddress,
          recipient: handshake.sender,
          ciphertext: "",
          timestamp: Date.now(),
          blockTimestamp: Date.now(),
          blockNumber: 0,
          direction: "outgoing" as const,
          decrypted: `Request accepted: "${responseMessage}"`,
          read: true,
          nonce: 0,
          dedupKey: `handshake-accepted-${handshake.id}`,
          type: "system" as const,
          ownerAddress: currentAddress,
          status: "pending" as const,
        };

        await addMessage(acceptanceMessage);

        addLog(
          `✅ Handshake accepted from ${handshake.sender.slice(
            0,
            8
          )}...: "${responseMessage}"`
        );
      } catch (error) {
        console.error("Failed to accept handshake:", error);
        addLog(
          `✗ Failed to accept handshake: ${
            error instanceof Error ? error.message : "Unknown error"
          }`
        );
      }
    },
    [
      address,
      baseAddress,
      executor,
      identityKeyPair,
      identityProof,
      getCurrentSigner,
      addLog,
      updateContact,
      removePendingHandshake,
      addMessage,
      setSelectedContact,
    ]
  );

  const sendMessageToContact = useCallback(
    async (contact: Contact, messageText: string) => {
      const currentAddress = address || baseAddress;

      if (
        !executor ||
        !currentAddress ||
        !contact.identityPubKey ||
        !identityKeyPair
      ) {
        addLog("✗ Contact not established or missing data");
        return;
      }

      setLoading(true);
      try {
        const topic = generateConversationTopic(
          currentAddress,
          contact.address
        );
        const timestamp = Math.floor(Date.now() / 1000);
        const identityAsSigningKey = {
          publicKey: identityKeyPair.signingPublicKey,
          secretKey: identityKeyPair.signingSecretKey,
        };

        const expectedNonce = Number(getNextNonce(currentAddress, topic)) + 1;

        const pendingMessage = {
          id: generateTempMessageId(),
          topic,
          sender: currentAddress,
          recipient: contact.address,
          ciphertext: "",
          timestamp: timestamp * 1000,
          blockTimestamp: Date.now(),
          blockNumber: 0,
          direction: "outgoing" as const,
          decrypted: messageText,
          read: true,
          nonce: expectedNonce,
          dedupKey: `${currentAddress}:${topic}:${expectedNonce}`,
          type: "text" as const,
          ownerAddress: currentAddress,
          status: "pending" as const,
        };

        await addMessage(pendingMessage);

        await sendEncryptedMessage({
          executor,
          topic,
          message: messageText,
          recipientPubKey: contact.identityPubKey,
          senderAddress: currentAddress,
          senderSignKeyPair: identityAsSigningKey,
          timestamp,
        });

        const updatedContact: Contact = {
          ...contact,
          lastMessage: messageText,
          lastTimestamp: Date.now(),
        };
        await updateContact(updatedContact);

        addLog(
          `Message sent to ${contact.address.slice(0, 8)}...: "${messageText}"`
        );
      } catch (error) {
        console.error("Failed to send message:", error);
        addLog(
          `✗ Failed to send message: ${
            error instanceof Error ? error.message : "Unknown error"
          }`
        );
      } finally {
        setLoading(false);
      }
    },
    [
      address,
      baseAddress,
      executor,
      identityKeyPair,
      addLog,
      addMessage,
      updateContact,
      setLoading,
    ]
  );

  return {
    sendHandshake,
    acceptHandshake,
    sendMessageToContact,
  };
};
