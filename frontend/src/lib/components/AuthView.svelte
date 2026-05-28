<script>
  import { LoaderCircle, LogIn } from "lucide-svelte";

  /** @type {"signin" | "register"} */
  export let authMode;
  /** @type {{ name: string, email: string, password: string }} */
  export let authForm;
  export let loadingAuth = false;
  export let errorMessage = "";
  export let noticeMessage = "";
  export let onModeChange = (_mode) => {};
  export let onFormChange = (_form) => {};
  export let onSubmit = () => {};

  function updateField(field, value) {
    onFormChange({ ...authForm, [field]: value });
  }
</script>

<main class="auth-page">
  <section class="auth-panel">
    <div class="auth-card">
      <div class="auth-brand">
        <div class="brand-row">
          <span class="brand-mark" aria-hidden="true"></span>
          <span>Tasktify</span>
        </div>
      </div>

      <h1>{authMode === "register" ? "Create account" : "Welcome back"}</h1>

      <div class="segmented" aria-label="Authentication mode">
        <button
          type="button"
          class:active={authMode === "signin"}
          on:click={() => onModeChange("signin")}
        >
          Sign in
        </button>
        <button
          type="button"
          class:active={authMode === "register"}
          on:click={() => onModeChange("register")}
        >
          Register
        </button>
      </div>

      <form class="auth-form" on:submit|preventDefault={onSubmit}>
        {#if authMode === "register"}
          <label>
            <span>Name</span>
            <input
              value={authForm.name}
              autocomplete="name"
              required
              on:input={(event) => updateField("name", event.currentTarget.value)}
            />
          </label>
        {/if}

        <label>
          <span>Email</span>
          <input
            value={authForm.email}
            type="email"
            autocomplete="email"
            required
            on:input={(event) => updateField("email", event.currentTarget.value)}
          />
        </label>

        <label>
          <span>Password</span>
          <input
            value={authForm.password}
            type="password"
            autocomplete={authMode === "register" ? "new-password" : "current-password"}
            minlength="6"
            required
            on:input={(event) => updateField("password", event.currentTarget.value)}
          />
        </label>

        {#if errorMessage}
          <p class="form-error">{errorMessage}</p>
        {/if}
        {#if noticeMessage}
          <p class="form-notice">{noticeMessage}</p>
        {/if}

        <button class="button-primary" type="submit" disabled={loadingAuth}>
          {#if loadingAuth}
            <LoaderCircle class="spin" size={18} aria-hidden="true" />
          {:else}
            <LogIn size={18} aria-hidden="true" />
          {/if}
          {authMode === "register" ? "Create account" : "Sign in"}
        </button>
      </form>
    </div>
  </section>
</main>
