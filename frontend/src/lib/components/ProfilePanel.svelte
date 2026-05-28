<script>
  import { User } from "lucide-svelte";

  /** @type {Record<string, any> | null} */
  export let profile = null;
  /** @type {Record<string, any> | null} */
  export let accessJwt = null;
</script>

<section class="tool-panel">
  <div class="panel-head">
    <div>
      <h2>Profile</h2>
    </div>
    <User size={20} aria-hidden="true" />
  </div>

  <dl class="detail-list compact">
    <div>
      <dt>Name</dt>
      <dd>{profile?.name || "-"}</dd>
    </div>
    <div>
      <dt>Email</dt>
      <dd>{profile?.email || accessJwt?.payload?.email || "-"}</dd>
    </div>
    <div>
      <dt>Security</dt>
      <dd>Falcon Precomputed 512</dd>
    </div>
  </dl>
</section>
