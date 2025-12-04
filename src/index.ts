import axios, { isAxiosError, type AxiosInstance } from 'axios';

/**
 * Options for configuring the AgentiumClient.
 */
export interface AgentiumClientOptions {
  /**
   * The base URL of the Agentium API.
   * @default https://api.agentium.network
   */
  baseURL?: string;
}

/**
 * Represents the status of a user's badge.
 */
export interface Badge {
  status: string;
}

/**
 * The response payload from a successful connect identity call.
 */
export interface ConnectIdentityResponse {
  /**
   * The user's Privy ID.
   */
  privy_user_id: string;
  /**
   * The user's Decentralized Identifier (DID).
   */
  did: string;
  /**
   * Information about the user's badge status.
   */
  badge: Badge;
}

/**
 * Custom error class for API-related errors from the AgentiumClient.
 */
export class AgentiumApiError extends Error {
  public readonly statusCode?: number;

  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = 'AgentiumApiError';
    this.statusCode = statusCode;
  }
}

/**
 * A client for interacting with the Agentium API.
 */
export class AgentiumClient {
  private readonly axiosInstance: AxiosInstance;
  private readonly DEFAULT_BASE_URL = 'https://api.agentium.network';
  private readonly CONNECT_PATH = '/v1/identity/connect';

  /**
   * Creates an instance of the AgentiumClient.
   * @param options - Configuration options for the client.
   */
  constructor(options: AgentiumClientOptions = {}) {
    const baseURL = options.baseURL || this.DEFAULT_BASE_URL;
    this.axiosInstance = axios.create({
      baseURL: baseURL,
    });
  }

  /**
   * Connects a Google identity to an Agentium identity.
   * @param googleToken - The JWT token obtained from Google Sign-In.
   * @returns A promise that resolves with the connection response, containing the user's DID and Privy ID.
   * @throws {AgentiumApiError} Will throw a custom API error if the call fails.
   *  - **400 (Bad Request):** The request was malformed (e.g., missing `id_token`).
   *  - **401 (Unauthorized):** The provided JWT token is invalid or expired.
   *  - **500 (Internal Server Error):** An unexpected error occurred on the server.
   */
  async connectGoogleIdentity(googleToken: string): Promise<ConnectIdentityResponse> {
    try {
      const response = await this.axiosInstance.post<ConnectIdentityResponse>(this.CONNECT_PATH, {
        id_token: googleToken,
      });
      return response.data;
    } catch (error) {
      if (isAxiosError(error)) {
        throw new AgentiumApiError(error.message, error.response?.status);
      }
      // Re-throw other unexpected errors
      throw error;
    }
  }
}