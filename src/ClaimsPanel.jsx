export default function ClaimsPanel({ claims }) {
  if (claims.length === 0) return null;
  return (
    <section className="panel" data-ui>
      <h2>Registered claims</h2>
      <dl className="claims">
        {claims.map((claim) => (
          <div key={claim.claim} className="claim">
            <dt>
              {claim.label} <code>{claim.claim}</code>
              <span className="sr-only">{claim.description}</span>
            </dt>
            <dd>
              {claim.utc ? (
                <>
                  <span className="num">{claim.utc}</span>
                  <span className="relative">{claim.relative}</span>
                </>
              ) : (
                <span className="num">{claim.value}</span>
              )}
              {claim.flag && (
                <span className="pill" data-flag={claim.flag}>
                  {claim.flag}
                </span>
              )}
            </dd>
          </div>
        ))}
      </dl>
      <details className="claim-details"><summary>About claims</summary><p>Time flags use this device's clock. They are separate from the signature check, and issuer and audience are shown but not validated.</p></details>
    </section>
  );
}
