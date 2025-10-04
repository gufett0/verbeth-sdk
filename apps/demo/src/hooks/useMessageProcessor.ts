// apps/demo/src/hooks/useMessageProcessor.ts

import { useState, useEffect, useCallback } from "react";
import { AbiCoder } from "ethers";
import {
  decryptMessage,
  parseHandshakePayload,
  verifyHandshakeIdentity,
  IdentityKeyPair,
  decodeUnifiedPubKeys,
  verifyAndExtractHandshakeResponseKeys,
  deriveDuplexTopics,
  verifyDerivedDuplexTopics,
  computeTagFromInitiator,
  pickOutboundTopic
} from "@verbeth/sdk";

import { dbService } from "../services/DbService.js";
import {
  Contact,
  Message,
  PendingHandshake,
  ProcessedEvent,
  MessageProcessorResult,
  MessageDirection,
  MessageType,
  ContactStatus,
  generateTempMessageId,
} from "../types.js";

interface UseMessageProcessorProps {
  readProvider: any;
  address: string | undefined;
  identityKeyPair: IdentityKeyPair | null;
  onLog: (message: string) => void;
}

export const useMessageProcessor = ({
  readProvider,
  address,
  identityKeyPair,
  onLog,
}: UseMessageProcessorProps): MessageProcessorResult => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [pendingHandshakes, setPendingHandshakes] = useState<
    PendingHandshake[]
  >([]);
  const [contacts, setContacts] = useState<Contact[]>([]);

  const hexToUint8Array = (hex: string): Uint8Array => {
    const cleanHex = hex.replace("0x", "");
    return new Uint8Array(
      cleanHex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );
  };

  const generateMessageId = (
    txHash: string,
    log: { logIndex?: number; index?: number }
  ): string => {
    const idx =
      typeof log.logIndex !== "undefined"
        ? log.logIndex
        : typeof log.index !== "undefined"
        ? log.index
        : 0;
    return `${txHash}-${idx}`;
  };

  const generateDedupKey = (
    sender: string,
    topic: string,
    nonce: number
  ): string => {
    return `${sender}:${topic}:${nonce}`;
  };

  // Load data from database
  const loadFromDatabase = useCallback(async () => {
    if (!address) return;

    try {
      const [dbContacts, dbMessages, dbPendingHandshakes] = await Promise.all([
        dbService.getAllContacts(address),
        dbService.getAllMessages(address, 100),
        dbService.getAllPendingHandshakes(address),
      ]);

      setContacts(dbContacts);
      setMessages(dbMessages);
      setPendingHandshakes(dbPendingHandshakes);

      onLog(
        `Loaded from DB for ${address.slice(0, 8)}...: ${
          dbContacts.length
        } contacts, ${dbMessages.length} messages, ${
          dbPendingHandshakes.length
        } pending handshakes`
      );
    } catch (error) {
      onLog(`✗ Failed to load from database: ${error}`);
    }
  }, [address, onLog]);

  // Process handshake log
  const processHandshakeLog = useCallback(
    async (event: ProcessedEvent): Promise<void> => {
      if (!address || !readProvider) return;

      try {
        const log = event.rawLog;
        const abiCoder = new AbiCoder();
        const decoded = abiCoder.decode(["bytes", "bytes", "bytes"], log.data);
        const [
          identityPubKeyBytes,
          ephemeralPubKeyBytes,
          plaintextPayloadBytes,
        ] = decoded;

        const unifiedPubKeys = hexToUint8Array(identityPubKeyBytes);
        const decodedKeys = decodeUnifiedPubKeys(unifiedPubKeys);

        if (!decodedKeys) {
          onLog("✗ Failed to decode unified public keys");
          return;
        }

        const identityPubKey = decodedKeys.identityPubKey;
        const signingPubKey = decodedKeys.signingPubKey;
        const ephemeralPubKey = hexToUint8Array(ephemeralPubKeyBytes);
        const plaintextPayload = new TextDecoder().decode(
          hexToUint8Array(plaintextPayloadBytes)
        );

        const cleanSenderAddress = "0x" + log.topics[2].slice(-40);
        const recipientHash = log.topics[1];

        let handshakeContent;
        let hasValidIdentityProof = false;

        try {
          handshakeContent = parseHandshakePayload(plaintextPayload);
          hasValidIdentityProof = true;
        } catch (error) {
          handshakeContent = {
            plaintextPayload: plaintextPayload,
            identityProof: null,
          };
          hasValidIdentityProof = false;
        }

        // Verify identity if we have a valid identity proof
        let isVerified = false;
        if (hasValidIdentityProof) {
          try {
            const handshakeEvent = {
              recipientHash,
              sender: cleanSenderAddress,
              pubKeys: identityPubKeyBytes,
              ephemeralPubKey: ephemeralPubKeyBytes,
              plaintextPayload: plaintextPayload,
            };

            isVerified = await verifyHandshakeIdentity(
              handshakeEvent,
              readProvider
            );
          } catch (error) {
            onLog(`Failed to verify handshake identity: ${error}`);
          }
        }

        const pendingHandshake: PendingHandshake = {
          id: log.transactionHash,
          ownerAddress: address,
          sender: cleanSenderAddress,
          identityPubKey,
          signingPubKey,
          ephemeralPubKey,
          message: handshakeContent.plaintextPayload,
          timestamp: Date.now(),
          blockNumber: log.blockNumber,
          verified: isVerified,
        };

        await dbService.savePendingHandshake(pendingHandshake);

        setPendingHandshakes((prev) => {
          const existing = prev.find((h) => h.id === pendingHandshake.id);
          if (existing) return prev;
          return [...prev, pendingHandshake];
        });

        const handshakeMessage: Message = {
          id: generateTempMessageId(),
          topic: "",
          sender: cleanSenderAddress,
          recipient: address,
          ciphertext: "",
          timestamp: Date.now(),
          blockTimestamp: Date.now(),
          blockNumber: log.blockNumber,
          direction: "incoming" as const,
          decrypted: `Request received: "${handshakeContent.plaintextPayload}"`,
          read: true,
          nonce: 0,
          dedupKey: `handshake-received-${log.transactionHash}`,
          type: "system" as const,
          ownerAddress: address,
          status: "confirmed" as const,
          verified: isVerified,
        };

        await dbService.saveMessage(handshakeMessage);
        setMessages((prev) => [...prev, handshakeMessage]);

        onLog(
          `📨 Handshake received from ${cleanSenderAddress.slice(0, 8)}... ${
            isVerified ? "✅" : "⚠️"
          }: "${handshakeContent.plaintextPayload}"`
        );
      } catch (error) {
        onLog(`✗ Failed to process handshake log: ${error}`);
      }
    },
    [address, readProvider, onLog]
  );

  // Process handshake response log - load contacts from DB
  const processHandshakeResponseLog = useCallback(
    async (event: ProcessedEvent): Promise<void> => {
      if (!address || !readProvider) return;

      try {
        const log = event.rawLog;

        // decode both responderEphemeralR and ciphertext from data
        const abiCoder = new AbiCoder();
        const [responderEphemeralRBytes, ciphertextBytes] = abiCoder.decode(
          ["bytes32", "bytes"],
          log.data
        );

        const ciphertextJson = new TextDecoder().decode(
          hexToUint8Array(ciphertextBytes)
        );

        const responder = "0x" + log.topics[2].slice(-40);
        const inResponseTo = log.topics[1];

        // Load fresh contacts from database
        const currentContacts = await dbService.getAllContacts(address);

        onLog(
          `🔍 Debug: Loaded ${currentContacts.length} contacts from DB for handshake response`
        );

        // Find the contact this response is for
        const contact = currentContacts.find(
          (c) =>
            c.address.toLowerCase() === responder.toLowerCase() &&
            c.status === "handshake_sent"
        );

        if (!contact || !contact.ephemeralKey) {
          onLog(
            `❓ Received handshake response from unknown contact: ${responder.slice(
              0,
              8
            )}...`
          );
          return;
        }

        const responseEvent = {
          inResponseTo,
          responder,
          responderEphemeralR: responderEphemeralRBytes,
          ciphertext: ciphertextJson,
        };

        const result = await verifyAndExtractHandshakeResponseKeys(
          responseEvent,
          contact.ephemeralKey, // initiator's ephemeral secret key
          readProvider
        );

        if (!result.isValid || !result.keys) {
          onLog(
            `❌ Failed to verify handshake response from ${responder.slice(
              0,
              8
            )}... - invalid signature or tag mismatch`
          );
          return;
        }

        const { identityPubKey, signingPubKey, ephemeralPubKey, note } =
          result.keys;

        if (!identityKeyPair) {
          onLog(`❌ Cannot verify duplex topics: identityKeyPair is null`);
          return;
        }

        const saltHex = computeTagFromInitiator(
          contact.ephemeralKey, // Alice's ephemeral secret (stored when she sent handshake)
          hexToUint8Array(responderEphemeralRBytes) // Bob's public R from the response event
        );
        const salt = Uint8Array.from(Buffer.from(saltHex.slice(2), "hex"));

        const duplexTopics = deriveDuplexTopics(
          identityKeyPair.secretKey, // Alice's identity secret key
          identityPubKey, // Bob's identity public key (from response)
          salt 
        );
        const isValidTopics = verifyDerivedDuplexTopics({
          myIdentitySecretKey: identityKeyPair.secretKey,
          theirIdentityPubKey: identityPubKey,
          topicInfo: {
            out: duplexTopics.topicOut,
            in: duplexTopics.topicIn,
            chk: duplexTopics.checksum,
          },
          salt
        });
        if (!isValidTopics) {
          onLog(
            `❌ Invalid duplex topics checksum for ${responder.slice(0, 8)}...`
          );
          return;
        }

        onLog(
          `✅ Handshake response verified from ${responder.slice(0, 8)}...`
        );

        // Update contact to established
        const updatedContact: Contact = {
          ...contact,
          status: "established" as ContactStatus,
          identityPubKey,
          signingPubKey,
          ephemeralKey: undefined,//ephemeralPubKey, // Store responder's ephemeral key
          topicOutbound: pickOutboundTopic(true, duplexTopics),   // Alice is initiator
          topicInbound: pickOutboundTopic(false, duplexTopics),   // Bob is responder
          lastMessage: note || "Handshake accepted",
          lastTimestamp: Date.now(),
        };

        await dbService.saveContact(updatedContact);

        // Update state
        setContacts((prev) =>
          prev.map((c) =>
            c.address.toLowerCase() === responder.toLowerCase()
              ? updatedContact
              : c
          )
        );

        onLog(
          `🤝 Handshake completed with ${responder.slice(0, 8)}... ✅: "${
            note || "No message"
          }"`
        );

        // Add handshake response message to chat
        //const conversationTopic = generateConversationTopic(address, responder);
        const responseMessage: Message = {
          id: generateTempMessageId(),
          topic: updatedContact.topicInbound || "",
          sender: responder,
          recipient: address,
          ciphertext: "",
          timestamp: Date.now(),
          blockTimestamp: Date.now(),
          blockNumber: 0,
          direction: "incoming" as const,
          decrypted: `Request accepted: "${note || "No message"}"`,
          read: true,
          nonce: 0,
          dedupKey: `handshake-response-${inResponseTo}`,
          type: "system" as const,
          ownerAddress: address,
          status: "confirmed" as const,
          verified: true, // Always true if verifyAndExtractHandshakeResponseKeys returned isValid: true
        };

        await dbService.saveMessage(responseMessage);
        setMessages((prev) => [...prev, responseMessage]);
      } catch (error) {
        onLog(`✗ Failed to process handshake response log: ${error}`);
        console.error("Full error:", error);
      }
    },
    [address, readProvider, onLog, identityKeyPair]
  );

  // Process message log - load contacts from DB and update lastMessage
  const processMessageLog = useCallback(
    async (event: ProcessedEvent): Promise<void> => {
      if (!address || !identityKeyPair) return;

      try {
        const log = event.rawLog;
        const abiCoder = new AbiCoder();
        const decoded = abiCoder.decode(
          ["bytes", "uint256", "uint256"],
          log.data
        );
        const [ciphertextBytes, timestamp, nonce] = decoded;
        const topic = log.topics[2];

        const sender = "0x" + log.topics[1].slice(-40);

        const ciphertextJson = new TextDecoder().decode(
          hexToUint8Array(ciphertextBytes)
        );
        const isOurMessage = sender.toLowerCase() === address.toLowerCase();

        onLog(
          `🔍 Processing message log: sender=${sender.slice(
            0,
            8
          )}..., isOurMessage=${isOurMessage}, topic=${topic.slice(
            0,
            10
          )}..., nonce=${Number(nonce)}`
        );

        if (isOurMessage) {
          // This is our own message appearing on-chain, update the outgoing message status
          onLog(
            `🔄 Confirming our outgoing message: topic=${topic.slice(
              0,
              10
            )}..., nonce=${Number(nonce)}`
          );

          let existingOutgoingMessage = await dbService.findPendingMessage(
            address, // sender
            topic, // topic (usa quello decodificato dal log)
            Number(nonce), // nonce
            address // owner (che per outgoing == sender)
          );

          // ✅ FALLBACK
          if (!existingOutgoingMessage) {
            const potentialDedupKey = generateDedupKey(
              address,
              topic,
              Number(nonce)
            );
            existingOutgoingMessage = await dbService.findMessageByDedupKey(
              potentialDedupKey
            );

            if (existingOutgoingMessage) {
              onLog(`Found message by dedupKey: ${potentialDedupKey}`);
            }
          }

          if (existingOutgoingMessage) {
            // ✅ Update the outgoing message with on-chain confirmation
            const newId = generateMessageId(log.transactionHash, log);

            const updatedMessage: Message = {
              ...existingOutgoingMessage,
              id: newId,
              blockNumber: log.blockNumber,
              blockTimestamp: Date.now(),
              ciphertext: ciphertextJson,
              topic: topic, // Use the actual on-chain topic
              nonce: Number(nonce), // Use the actual on-chain nonce
              dedupKey: generateDedupKey(address, topic, Number(nonce)),
              status: "confirmed",
            };

            // Replace old message with confirmed one
            await dbService.updateMessage(
              existingOutgoingMessage.id,
              updatedMessage
            );

            // Update state
            setMessages((prev) =>
              prev.map((m) =>
                m.id === existingOutgoingMessage.id ? updatedMessage : m
              )
            );

            onLog(
              `Outgoing message confirmed on-chain: "${existingOutgoingMessage.decrypted?.slice(
                0,
                30
              )}..." (${existingOutgoingMessage.id} → ${newId})`
            );
          } else {
            onLog(
              `Couldn't find matching outgoing message for confirmation (topic: ${topic.slice(
                0,
                10
              )}..., nonce: ${Number(
                nonce
              )}) - this might be a message from another session`
            );
          }

          return; // Don't process as incoming message since it's our own
        }

        const currentContacts = await dbService.getAllContacts(address);

        const contact = currentContacts.find(
          (c) =>
            c.address.toLowerCase() === sender.toLowerCase() &&
            c.status === "established"
        );

        if (!contact || !contact.identityPubKey || !contact.signingPubKey) {
          onLog(
            `❓ Received message from unknown contact: ${sender.slice(0, 8)}...`
          );
          return;
        }

        if (contact.topicInbound && topic !== contact.topicInbound) {
          onLog(
            `❌ Message topic mismatch from ${sender.slice(
              0,
              8
            )}... - expected ${contact.topicInbound.slice(
              0,
              10
            )}..., got ${topic.slice(0, 10)}...`
          );
          return;
        }

        const decryptedMessage = decryptMessage(
          ciphertextJson,
          identityKeyPair.secretKey,
          contact.signingPubKey
        );

        if (!decryptedMessage) {
          onLog(`✗ Failed to decrypt message from ${sender.slice(0, 8)}...`);
          return;
        }

        // Create message object
        const message: Message = {
          id: generateMessageId(log.transactionHash, log),
          topic: topic,
          sender: sender,
          recipient: address,
          ciphertext: ciphertextJson,
          timestamp: Number(timestamp) * 1000, // Convert to milliseconds
          blockTimestamp: Date.now(), // Will be updated with actual block timestamp if needed
          blockNumber: log.blockNumber,
          direction: "incoming" as MessageDirection,
          decrypted: decryptedMessage,
          read: false,
          nonce: Number(nonce),
          dedupKey: generateDedupKey(sender, topic, Number(nonce)),
          type: "text" as MessageType,
          ownerAddress: address,
          status: "confirmed",
        };

        // Save to database (will handle deduplication)
        const saved = await dbService.saveMessage(message);

        if (saved) {
          // Update state
          setMessages((prev) => {
            const existing = prev.find((m) => m.id === message.id);
            if (existing) return prev;
            return [...prev, message];
          });

          // ✅ FIXED: Update contact's lastMessage and lastTimestamp when receiving a message
          const updatedContact: Contact = {
            ...contact,
            lastMessage: decryptedMessage,
            lastTimestamp: Date.now(),
          };

          await dbService.saveContact(updatedContact);

          // Update contacts state
          setContacts((prev) =>
            prev.map((c) =>
              c.address.toLowerCase() === sender.toLowerCase()
                ? updatedContact
                : c
            )
          );

          onLog(`Message from ${sender.slice(0, 8)}...: "${decryptedMessage}"`);
        }
      } catch (error) {
        onLog(`✗ Failed to process message log: ${error}`);
      }
    },
    [address, identityKeyPair, onLog]
  );

  // ✅ FIXED: Main event processing function - NOW STABLE!
  const processEvents = useCallback(
    async (events: ProcessedEvent[]) => {
      for (const event of events) {
        switch (event.eventType) {
          case "handshake":
            await processHandshakeLog(event);
            break;
          case "handshake_response":
            await processHandshakeResponseLog(event); // ✅ Removed currentContacts parameter
            break;
          case "message":
            await processMessageLog(event); // ✅ Removed currentContacts parameter
            break;
        }
      }
    },
    [processHandshakeLog, processHandshakeResponseLog, processMessageLog]
  );
  // ✅ Now it only depends on the processing functions, not on contacts state!

  // Helper functions for UI
  const addMessage = useCallback(
    async (message: Message) => {
      if (!address) return;

      const messageWithOwner = { ...message, ownerAddress: address };
      const saved = await dbService.saveMessage(messageWithOwner);
      if (saved) {
        setMessages((prev) => [...prev, messageWithOwner]);
      }
    },
    [address]
  );

  const removePendingHandshake = useCallback(async (id: string) => {
    await dbService.deletePendingHandshake(id);
    setPendingHandshakes((prev) => prev.filter((h) => h.id !== id));
  }, []);

  const updateContact = useCallback(
    async (contact: Contact) => {
      if (!address) return;
      const contactWithOwner = { ...contact, ownerAddress: address };
      await dbService.saveContact(contactWithOwner);

      // Always reload all contacts from the DB after update to ensure state is correct
      const allContacts = await dbService.getAllContacts(address);
      setContacts(allContacts);
    },
    [address]
  );

  useEffect(() => {
    if (address) {
      setMessages([]);
      setContacts([]);
      setPendingHandshakes([]);
      loadFromDatabase();
    }
  }, [address, loadFromDatabase]);

  return {
    messages,
    pendingHandshakes,
    contacts,
    addMessage,
    removePendingHandshake,
    updateContact,
    processEvents,
  };
};
