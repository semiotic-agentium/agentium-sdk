import axios, { AxiosInstance } from 'axios';

interface AgentiumClientOptions {
  baseURL?: string;
}

export class AgentiumClient {
  private axiosInstance: AxiosInstance;
  private readonly DEFAULT_BASE_URL = 'https://api.agentium.network';

  constructor(options: AgentiumClientOptions = {}) {
    const baseURL = options.baseURL || this.DEFAULT_BASE_URL;
    this.axiosInstance = axios.create({
      baseURL: baseURL,
    });
  }

  async connectGoogleIdentity(googleToken: string): Promise<any> {
    try {
      const response = await this.axiosInstance.post('/v1/identity/connect', {
        id_token: googleToken,
      });
      return response.data;
    } catch (error) {
      // Re-throw the error to be caught by the test's rejects.toThrow
      throw error;
    }
  }
}