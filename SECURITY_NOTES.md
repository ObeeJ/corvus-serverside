# Security Notes for Corvus Payment System

## Environment Files

### `.env.example`
- Contains example/placeholder values
- Safe to commit to version control
- Used as a template for developers

### `.env`
- **CONTAINS ACTUAL SECRETS**
- **NEVER COMMIT TO VERSION CONTROL**
- Already in `.gitignore` for safety
- Contains test keys for development

## Secret Management

### Development (Current Setup)
- Test Paystack keys are in `.env`
- These are safe for development but should not be used in production
- JWT secret is a development-only value

### Production Deployment
1. **Generate new secrets** for production:
   - New Paystack live keys
   - Strong JWT secret (32+ random characters)
   - Database credentials

2. **Use secure secret management**:
   - AWS Secrets Manager
   - HashiCorp Vault
   - Environment variables in your deployment platform

3. **Rotate keys regularly**:
   - JWT secrets every 90 days
   - API keys when team members leave

## Crypto Payment Security

### Address Verification
- Crypto addresses are hardcoded in `internal/billing/paystack.go`
- Verify addresses match your wallet addresses before deployment
- Consider using multi-sig wallets for production

### Transaction Verification
- Current implementation: manual verification via transaction hash
- Production recommendation: Use blockchain RPC nodes or indexers
- Implement rate limiting for verification endpoints

## Webhook Security

### Paystack Webhooks
- Webhook signature verification is implemented
- Ensure `PAYSTACK_SECRET_KEY` is set correctly
- Monitor webhook delivery failures

### Network Security
- Use HTTPS in production (`PUBLIC_URL` should be https://)
- Implement IP whitelisting if possible
- Rate limit webhook endpoints

## Database Security

### Connection Security
- Use SSL for database connections in production
- Restrict database access to application servers only
- Regular database backups

### Payment Data
- Payment records contain user IDs and transaction references
- Consider GDPR compliance for user data
- Implement data retention policies

## Best Practices Checklist

- [ ] `.env` is in `.gitignore` (already done)
- [ ] Test keys are not used in production
- [ ] JWT secrets are strong and rotated
- [ ] Database uses SSL in production
- [ ] Webhooks use HTTPS
- [ ] Crypto addresses are verified
- [ ] Rate limiting is enabled on payment endpoints
- [ ] Regular security audits of payment code