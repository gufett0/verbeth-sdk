interface IdentityCreationProps {
    loading: boolean;
    onCreateIdentity: () => void;
    onImportIdentity?: () => void;
    address: string;
}

export function IdentityCreation({
    loading,
    onCreateIdentity,
    onImportIdentity,
    address,
}: IdentityCreationProps) {
    return (
        <div className="flex items-center justify-center min-h-[60vh]">
            <div className="border border-gray-800 rounded-lg p-8 w-full max-w-md">
                <div className="text-center mb-6">
                    <h2 className="text-2xl font-semibold mb-2">
                        Create Your Identity
                    </h2>
                    <p className="text-sm text-gray-400">
                        {address
                            ? <>Connected as {address.slice(0, 8)}...{address.slice(-6)}</>
                            : "Not connected"}
                    </p>
                    <p className="text-sm text-gray-400 mt-2">
                        Choose how to set up your encrypted messaging identity
                    </p>
                </div>

                <div className="space-y-4">
                    <button
                        onClick={onCreateIdentity}
                        disabled={loading}
                        className="w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed rounded font-medium"
                    >
                        {loading ? "Creating..." : "Create New Identity"}
                    </button>

                    <button
                        onClick={onImportIdentity}
                        disabled={true}
                        className="w-full px-4 py-3 bg-gray-600 cursor-not-allowed rounded font-medium opacity-50"
                    >
                        Import Previous Identity (Coming Soon)
                    </button>
                </div>

                <div className="mt-6 text-xs text-gray-500 text-center">
                    <p>
                        Your identity keys are derived from your wallet signature and stored locally.
                        They enable end-to-end encrypted messaging on the blockchain.
                    </p>
                </div>
            </div>
        </div>
    );
}