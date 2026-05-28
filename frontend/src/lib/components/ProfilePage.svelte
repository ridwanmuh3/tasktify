<script>
  import { User } from "lucide-svelte";

  /** @type {Record<string, any> | null} */
  export let profile = null;
  /** @type {{ header?: Record<string, any>, payload?: Record<string, any>, signature?: string } | null} */
  export let accessJwt = null;

  $: header = accessJwt?.header || null;
  $: payload = accessJwt?.payload || null;
  $: signature = accessJwt?.signature || "";
  $: headerJson = header ? JSON.stringify(header, null, 2) : "";
  $: payloadJson = payload ? JSON.stringify(payload, null, 2) : "";
</script>

<section class="profile-page">
  <div class="section-head">
    <div>
      <h1>Profile</h1>
    </div>
    <User size={24} aria-hidden="true" />
  </div>

  <div class="profile-grid">
    <section class="tool-panel">
      <div class="panel-head">
        <div>
          <h2>Account</h2>
        </div>
      </div>

      <dl class="detail-list compact">
        <div>
          <dt>Name</dt>
          <dd>{profile?.name || payload?.name || "-"}</dd>
        </div>
        <div>
          <dt>Email</dt>
          <dd>{profile?.email || payload?.email || "-"}</dd>
        </div>
      </dl>
    </section>

    <section class="tool-panel jwt-panel">
      <div class="panel-head">
        <div>
          <h2>JWT</h2>
        </div>
      </div>

      {#if header && payload}
        <div class="jwt-stack">
          <section>
            <h3>Header</h3>
            <pre class="jwt-json">{headerJson}</pre>
          </section>
          <section>
            <h3>Payload</h3>
            <pre class="jwt-json">{payloadJson}</pre>
          </section>
          <section>
            <h3>Signature</h3>
            <code class="jwt-signature">{signature || "-"}</code>
          </section>
        </div>
      {:else}
        <p class="muted-text">No JWT found</p>
      {/if}
    </section>
  </div>
</section>
