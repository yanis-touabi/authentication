export interface EmailOptions {
  to: string;
  subject: string;
  template: string;
  context: Record<string, any>;
}

export interface EmailTemplateContext {
  name?: string;
  code?: string;
  link?: string;
  expiration?: string;
}
