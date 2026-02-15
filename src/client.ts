import axios from 'axios';
import { randomUUID } from 'crypto';

export interface OAuth2Config {
  clientId: string;
  clientSecret?: string;
  authUrl: string;
  tokenUrl: string;
  redirectUri: string;
  scopes?: string[];
}

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  tokenType?: string;
}

export class OAuth2Client {
  private config: OAuth2Config;
  private codeVerifier?: string;

  constructor(config: OAuth2Config) {
    this.config = config;
  }

  generateAuthUrl(): string {
    this.codeVerifier = randomUUID() + randomUUID();
    const state = randomUUID();
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      state,
      scope: this.config.scopes?.join(' ') || 'openid',
      code_challenge: this.codeVerifier.slice(0, 43),
      code_challenge_method: 'S256'
    });
    return `${this.config.authUrl}?${params}`;
  }

  async exchangeCode(code: string): Promise<TokenSet> {
    const res = await axios.post(this.config.tokenUrl, new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret || '',
      code,
      grant_type: 'authorization_code',
      redirect_uri: this.config.redirectUri,
      code_verifier: this.codeVerifier || ''
    }).toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return res.data;
  }

  async refresh(refreshToken: string): Promise<TokenSet> {
    const res = await axios.post(this.config.tokenUrl, new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret || '',
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    }).toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return res.data;
  }
}
