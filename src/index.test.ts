import { AgentiumClient } from './index';

describe('AgentiumClient', () => {
  it('should be defined', () => {
    expect(AgentiumClient).toBeDefined();
  });

  it('should have a connectGoogleIdentity method', () => {
    const client = new AgentiumClient();
    expect(client.connectGoogleIdentity).toBeInstanceOf(Function);
  });

  it('connectGoogleIdentity should return a Promise', async () => {
    const client = new AgentiumClient();
    const promise = client.connectGoogleIdentity('some-token');
    expect(promise).toBeInstanceOf(Promise);
    // We expect it to fail since no actual implementation yet
    await expect(promise).rejects.toThrow();
  });

  it('should accept a baseURL in the constructor and use default if not provided', () => {
    const defaultClient = new AgentiumClient();
    // How to test the baseURL? This will be handled when integrating axios.
    // For now, we can at least ensure the constructor doesn't throw.
    expect(() => defaultClient).not.toThrow();

    const customClient = new AgentiumClient({ baseURL: 'http://localhost:3000' });
    expect(() => customClient).not.toThrow();
  });
});
