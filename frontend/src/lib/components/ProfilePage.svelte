<script>
  import { User } from "lucide-svelte";

  /** @type {Record<string, any> | null} */
  export let profile = null;
  /** @type {{ payload?: Record<string, any> } | null} */
  export let accessJwt = null;

  $: payload = accessJwt?.payload || null;
  $: payloadEntries = payload ? Object.entries(payload) : [];
  $: payloadJson = payload ? JSON.stringify(payload, null, 2) : "";

  function claimValue(value) {
    if (value === null) {
      return "null";
    }
    if (value === undefined || value === "") {
      return "-";
    }
    if (typeof value === "object") {
      return JSON.stringify(value);
    }
    return String(value);
  }
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
          <h2>JWT payload</h2>
        </div>
      </div>

      {#if payload}
        <div class="claim-list">
          {#each payloadEntries as [key, value]}
            <div class="claim-row">
              <span class="claim-key">{key}</span>
              <code class="claim-value">{claimValue(value)}</code>
            </div>
          {/each}
        </div>

        <pre class="jwt-json">{payloadJson}</pre>
      {:else}
        <p class="muted-text">No JWT payload found</p>
      {/if}
    </section>
  </div>
</section>
