import { MessageDeduplicator } from "@verbeth/sdk";
import { VerbEthDatabase } from "./schema.js";
import type {
  StoredIdentity,
  Contact,
  Message,
  PendingHandshake,
} from "../types.js";

export class DbService {
  private readonly db: VerbEthDatabase;
  private readonly deduplicator: MessageDeduplicator;

  constructor() {
    this.db = new VerbEthDatabase();
    this.deduplicator = new MessageDeduplicator(10_000);
  }

  /* ----------------------------- ADDRESS HELPERS --------------------------- */
  private normalizeAddress(address: string): string {
    return address.toLowerCase();
  }

  /* ----------------------------- IDENTITIES -------------------------------- */
  async saveIdentity(identity: StoredIdentity) {
    const normalizedAddress = this.normalizeAddress(identity.address);
    console.log(
      `Saving identity for ${normalizedAddress.slice(
        0,
        8
      )}... (original: ${identity.address.slice(0, 8)})`
    );

    try {
      // Normalize the address before saving
      const normalizedIdentity = {
        ...identity,
        address: normalizedAddress,
      };

      const result = await this.db.identity.put(normalizedIdentity);
      console.log(
        `✅ Identity saved successfully for ${normalizedAddress.slice(0, 8)}...`
      );

      // Verify it was saved
      const verification = await this.db.identity.get(normalizedAddress);
      if (verification) {
        console.log(
          `Identity verified in DB for ${normalizedAddress.slice(0, 8)}...`
        );
      } else {
        console.error(
          `✗ Identity NOT found after save for ${normalizedAddress.slice(
            0,
            8
          )}...`
        );
      }

      return result;
    } catch (error) {
      console.error(
        `✗ Failed to save identity for ${normalizedAddress.slice(0, 8)}...:`,
        error
      );
      throw error;
    }
  }

  async getIdentity(address: string) {
    const normalizedAddress = this.normalizeAddress(address);
    console.log(
      `Looking for identity: ${normalizedAddress.slice(
        0,
        8
      )}... (original: ${address.slice(0, 8)})`
    );

    try {
      const result = await this.db.identity.get(normalizedAddress);
      if (result) {
      } else {
        // Debug: show all identities in DB
        const allIdentities = await this.db.identity.toArray();
        console.log(`Available identities in DB: ${allIdentities.length}`);
        allIdentities.forEach((id) => {
          console.log(`  - ${id.address} (${id.address.slice(0, 8)}...)`);
        });
      }
      return result;
    } catch (error) {
      console.error(
        `✗ Error getting identity for ${normalizedAddress.slice(0, 8)}...:`,
        error
      );
      return null;
    }
  }

  deleteIdentity(address: string) {
    const normalizedAddress = this.normalizeAddress(address);
    console.log(`Deleting identity for ${normalizedAddress.slice(0, 8)}...`);
    return this.db.identity.delete(normalizedAddress);
  }

  /* ------------------------------ CONTACTS --------------------------------- */
  saveContact(contact: Contact) {
    const normalizedContact = {
      ...contact,
      address: this.normalizeAddress(contact.address),
      ownerAddress: this.normalizeAddress(contact.ownerAddress),
    };
    console.log(
      `👤 Saving contact ${normalizedContact.address.slice(
        0,
        8
      )}... for owner ${normalizedContact.ownerAddress.slice(0, 8)}...`
    );
    return this.db.contacts.put(normalizedContact);
  }

  getContact(address: string, ownerAddress: string) {
    const normalizedAddress = this.normalizeAddress(address);
    const normalizedOwner = this.normalizeAddress(ownerAddress);
    return this.db.contacts
      .where("[address+ownerAddress]")
      .equals([normalizedAddress, normalizedOwner])
      .first();
  }

  async getAllContacts(ownerAddress: string) {
    const normalizedOwner = this.normalizeAddress(ownerAddress);

    const contacts = await this.db.contacts
      .where("ownerAddress")
      .equals(normalizedOwner)
      .toArray();

    const sorted = contacts.sort(
      (a, b) => (b.lastTimestamp ?? 0) - (a.lastTimestamp ?? 0)
    );
    return sorted;
  }

  updateContactStatus(address: string, status: Contact["status"]) {
    const normalizedAddress = this.normalizeAddress(address);
    return this.db.contacts.update(normalizedAddress, { status });
  }

  deleteContact(address: string) {
    const normalizedAddress = this.normalizeAddress(address);
    return this.db.contacts.delete(normalizedAddress);
  }

  /* ------------------------------ MESSAGES --------------------------------- */
  async saveMessage(message: Message): Promise<boolean> {
    if (
      this.deduplicator.isDuplicate(
        message.sender,
        message.topic,
        BigInt(message.nonce)
      )
    ) {
      console.debug(`Message ${message.dedupKey} already processed`);
      return false;
    }

    if (await this.db.messages.get(message.id)) {
      console.debug(`Message ${message.id} already in DB`);
      return false;
    }

    const normalizedMessage = {
      ...message,
      sender: this.normalizeAddress(message.sender),
      recipient: message.recipient
        ? this.normalizeAddress(message.recipient)
        : undefined,
      ownerAddress: this.normalizeAddress(message.ownerAddress),
    };

    if (
      normalizedMessage.direction === "outgoing" &&
      normalizedMessage.recipient
    ) {
      await this.updateContactLastMessage(
        normalizedMessage.recipient,
        normalizedMessage.ownerAddress,
        normalizedMessage.decrypted || "Encrypted message",
        normalizedMessage.timestamp
      );
    } else if (normalizedMessage.direction === "incoming") {
      await this.updateContactLastMessage(
        normalizedMessage.sender,
        normalizedMessage.ownerAddress,
        normalizedMessage.decrypted || "Encrypted message",
        normalizedMessage.timestamp
      );
    }

    console.log(
      `Saving new message from ${normalizedMessage.sender.slice(
        0,
        8
      )}... for owner ${normalizedMessage.ownerAddress.slice(0, 8)}...`
    );
    await this.db.messages.put(normalizedMessage);
    return true;
  }

  async updateMessage(
    messageId: string,
    updates: Partial<Message>
  ): Promise<boolean> {
    try {
      // If we're updating the ID, we need to handle it specially
      if (updates.id && updates.id !== messageId) {
        const oldMessage = await this.getMessage(messageId);
        if (oldMessage) {
          const newMessage = { ...oldMessage, ...updates };
          await this.deleteMessage(messageId);
          await this.saveMessage(newMessage);
          console.log(
            `Replaced message ${messageId.slice(
              0,
              8
            )}... with new ID ${updates.id?.slice(0, 8)}...`
          );
          return true;
        }
        return false;
      }

      const result = await this.db.messages.update(messageId, updates);
      console.log(
        `Updated message ${messageId.slice(0, 8)}... with:`,
        updates
      );
      return result > 0;
    } catch (error) {
      console.error(
        `✗ Failed to update message ${messageId.slice(0, 8)}...:`,
        error
      );
      return false;
    }
  }

async findPendingMessage(
  sender: string,
  topic: string,
  nonce: number,
  owner: string
): Promise<Message | undefined> {
  const normalizedSender = this.normalizeAddress(sender);
  const normalizedOwner = this.normalizeAddress(owner);
  

  // Try exact match first using compound index
  const exactMatch = await this.db.messages
    .where('[ownerAddress+sender+topic+nonce+status]')
    .equals([normalizedOwner, normalizedSender, topic, nonce, "pending"])
    .first();
    
  if (exactMatch) {
    console.log(`Found exact match!`, {
      messageId: exactMatch.id,
      messageTopic: exactMatch.topic.slice(0, 20) + "...",
      messageNonce: exactMatch.nonce
    });
    return exactMatch;
  } 
  
  // FALLBACK: Find by content and recent timestamp
  const recentPendingMessages = await this.db.messages
    .where('[ownerAddress+sender+status]')
    .equals([normalizedOwner, normalizedSender, "pending"])
    .reverse()
    .limit(3)
    .toArray();
    
  if (recentPendingMessages.length > 0) {
    console.log(`Using fallback matching: found ${recentPendingMessages.length} recent pending messages`);
    return recentPendingMessages[0]; // Most recent
  }
  
  return undefined;
}

  async findMessageByDedupKey(dedupKey: string): Promise<Message | undefined> {
    return this.db.messages
      .where('dedupKey')
      .equals(dedupKey)
      .first();
  }


  async updateContactLastMessage(
    address: string,
    ownerAddress: string,
    lastMessage: string,
    lastTimestamp?: number
  ) {
    const normalizedAddress = this.normalizeAddress(address);
    const normalizedOwner = this.normalizeAddress(ownerAddress);

    return this.db.contacts
      .where("ownerAddress")
      .equals(normalizedOwner)
      .filter((c) => c.address === normalizedAddress)
      .modify({
        lastMessage,
        lastTimestamp: lastTimestamp ?? Date.now(),
      });
  }

  getMessage(id: string) {
    return this.db.messages.get(id);
  }

  async getMessagesByContact(contact: string, ownerAddress: string, limit = 50) {
    const normalizedContact = this.normalizeAddress(contact);
    const normalizedOwner = this.normalizeAddress(ownerAddress);
    
    return this.db.messages
      .where('ownerAddress')
      .equals(normalizedOwner)
      .filter(m => 
        m.sender === normalizedContact || 
        m.recipient === normalizedContact
      )
      .reverse()
      .limit(limit)
      .toArray();
  }

  getMessagesByTopic(topic: string, limit = 50) {
    return this.db.messages
      .where("topic")
      .equals(topic)
      .reverse()
      .limit(limit)
      .toArray();
  }

  async getAllMessages(ownerAddress: string, limit = 100) {
    const normalizedOwner = this.normalizeAddress(ownerAddress);
    console.log(
      `Loading messages for owner ${normalizedOwner.slice(0, 8)}...`
    );
    const messages = await this.db.messages
      .where("ownerAddress")
      .equals(normalizedOwner)
      .toArray();

    const sorted = messages
      .sort((a, b) => b.blockTimestamp - a.blockTimestamp)
      .slice(0, limit);
    return sorted;
  }

  markMessageAsRead(id: string) {
    return this.db.messages.update(id, { read: true });
  }

  getUnreadMessagesCount() {
    return this.db.messages.filter((m) => !m.read).count();
  }

  deleteMessage(id: string) {
    return this.db.messages.delete(id);
  }

  /* ------------------------- PENDING HANDSHAKES --------------------------- */
  savePendingHandshake(h: PendingHandshake) {
    const normalizedHandshake = {
      ...h,
      sender: this.normalizeAddress(h.sender),
      ownerAddress: this.normalizeAddress(h.ownerAddress),
    };
    console.log(
      `...Saving pending handshake from ${normalizedHandshake.sender.slice(
        0,
        8
      )}... for owner ${normalizedHandshake.ownerAddress.slice(0, 8)}...`
    );
    return this.db.pendingHandshakes.put(normalizedHandshake);
  }

  getPendingHandshake(id: string) {
    return this.db.pendingHandshakes.get(id);
  }

  async getAllPendingHandshakes(ownerAddress: string) {
    const normalizedOwner = this.normalizeAddress(ownerAddress);
    const handshakes = await this.db.pendingHandshakes
      .where("ownerAddress")
      .equals(normalizedOwner)
      .toArray();

    const sorted = handshakes.sort((a, b) => b.timestamp - a.timestamp);
    return sorted;
  }

  deletePendingHandshake(id: string) {
    console.log(`Deleting pending handshake ${id.slice(0, 8)}...`);
    return this.db.pendingHandshakes.delete(id);
  }

  /* -------------------------------- SETTINGS ------------------------------ */
  setSetting(name: string, value: any) {
    return this.db.settings.put({ name, value });
  }
  async getSetting(name: string) {
    return (await this.db.settings.get(name))?.value;
  }
  deleteSetting(name: string) {
    return this.db.settings.delete(name);
  }

  /* --------------------------------- SYNC --------------------------------- */
  getLastKnownBlock() {
    return this.getSetting("lastKnownBlock");
  }
  setLastKnownBlock(n: number) {
    return this.setSetting("lastKnownBlock", n);
  }
  getOldestScannedBlock() {
    return this.getSetting("oldestScannedBlock");
  }
  setOldestScannedBlock(n: number) {
    return this.setSetting("oldestScannedBlock", n);
  }
  getInitialScanComplete(addr: string) {
    const normalizedAddr = this.normalizeAddress(addr);
    return this.getSetting(`initialScanComplete_${normalizedAddr}`);
  }
  setInitialScanComplete(addr: string, ok: boolean) {
    const normalizedAddr = this.normalizeAddress(addr);
    return this.setSetting(`initialScanComplete_${normalizedAddr}`, ok);
  }

  /* ------------------------------ UTILITIES ------------------------------- */
  async clearAllData() {
    console.log("🧹 Clearing all database data...");
    await this.db.transaction(
      "rw",
      [
        this.db.identity,
        this.db.contacts,
        this.db.messages,
        this.db.pendingHandshakes,
        this.db.settings,
      ],
      async () => {
        await this.db.identity.clear();
        await this.db.contacts.clear();
        await this.db.messages.clear();
        await this.db.pendingHandshakes.clear();
        await this.db.settings.clear();
      }
    );
    this.deduplicator.clear();
    console.log("✅ All database data cleared");
  }

  async clearUserData(addr: string) {
    const normalizedAddr = this.normalizeAddress(addr);
    console.log(`Clearing data for user ${normalizedAddr.slice(0, 8)}...`);
    await this.db.transaction(
      "rw",
      [
        this.db.identity,
        this.db.contacts,
        this.db.messages,
        this.db.pendingHandshakes,
        this.db.settings,
      ],
      async () => {
        await this.db.identity.delete(normalizedAddr);

        // Delete only data owned by this user
        await this.db.contacts
          .where("ownerAddress")
          .equals(normalizedAddr)
          .delete();
        await this.db.messages
          .where("ownerAddress")
          .equals(normalizedAddr)
          .delete();
        await this.db.pendingHandshakes
          .where("ownerAddress")
          .equals(normalizedAddr)
          .delete();

        const staleSettings = await this.db.settings
          .where("name")
          .startsWith(`initialScanComplete_${normalizedAddr}`)
          .toArray();
        for (const s of staleSettings) {
          await this.db.settings.delete(s.name);
        }
      }
    );
    this.deduplicator.clear();
    console.log(`✅ User data cleared for ${normalizedAddr.slice(0, 8)}...`);
  }

  /* ---------------------------- BACKUP / IMPORT --------------------------- */
  async exportData() {
    console.log("Exporting database...");
    const payload = {
      identity: await this.db.identity.toArray(),
      contacts: await this.db.contacts.toArray(),
      messages: await this.db.messages.toArray(),
      pendingHandshakes: await this.db.pendingHandshakes.toArray(),
      settings: await this.db.settings.toArray(),
      exportedAt: Date.now(),
    } as const;

    console.log(
      `✅ Exported ${payload.identity.length} identities, ${payload.contacts.length} contacts, ${payload.messages.length} messages`
    );
    return JSON.stringify(payload);
  }

  async importData(json: string) {
    console.log("...Importing database...");
    const data = JSON.parse(json);

    await this.db.transaction(
      "rw",
      [
        this.db.identity,
        this.db.contacts,
        this.db.messages,
        this.db.pendingHandshakes,
        this.db.settings,
      ],
      async () => {
        if (data.identity) await this.db.identity.bulkPut(data.identity);
        if (data.contacts) await this.db.contacts.bulkPut(data.contacts);
        if (data.messages) await this.db.messages.bulkPut(data.messages);
        if (data.pendingHandshakes)
          await this.db.pendingHandshakes.bulkPut(data.pendingHandshakes);
        if (data.settings) await this.db.settings.bulkPut(data.settings);
      }
    );
    console.log("✅ Database import completed");
  }

  /* -------------------------------- ACCOUNT SWITCH -------------------------------- */
  async switchAccount(newAddress: string) {
    const normalizedAddress = this.normalizeAddress(newAddress);

    this.deduplicator.clear();

    const allIdentities = await this.db.identity.toArray();
    console.log(`Database state: ${allIdentities.length} total identities`);
    allIdentities.forEach((id) => {
      console.log(
        `  - ${id.address} (derived: ${new Date(
          id.derivedAt
        ).toLocaleString()})`
      );
    });

    const [contacts, messages, handshakes] = await Promise.all([
      this.getAllContacts(normalizedAddress),
      this.getAllMessages(normalizedAddress, 1000),
      this.getAllPendingHandshakes(normalizedAddress),
    ]);

    console.log(
      `Data for ${normalizedAddress.slice(0, 8)}...: ${
        contacts.length
      } contacts, ${messages.length} messages, ${
        handshakes.length
      } pending handshakes`
    );
  }

  /* ------------------------------ CLEANUP --------------------------------- */
  close() {
    console.log("Closing database connection...");
    this.db.close();
  }
}

export const dbService = new DbService();
