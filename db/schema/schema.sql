--
-- PostgreSQL database dump
--


-- Dumped from database version 16.11 (Ubuntu 16.11-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.11 (Ubuntu 16.11-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: internal_set_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.internal_set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
	NEW.updated_at = now();
	RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_hash text NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    scope text DEFAULT ''::text,
    expires_at timestamp with time zone NOT NULL,
    is_revoked boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: authorization_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.authorization_codes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    code text NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    scope text DEFAULT ''::text,
    state text,
    code_challenge text,
    code_challenge_method character varying(10),
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    is_revoked boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text,
    client_secret_hash text NOT NULL,
    redirect_uris text[] NOT NULL,
    grant_types text[] DEFAULT ARRAY['authorization_code'::text] NOT NULL,
    is_active boolean DEFAULT true,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    is_confidential boolean DEFAULT true NOT NULL,
    allow_refresh_tokens boolean DEFAULT false NOT NULL
);


--
-- Name: oauth_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    name text NOT NULL,
    display_name text NOT NULL,
    provider_client_id text NOT NULL,
    provider_client_secret text NOT NULL,
    auth_url text NOT NULL,
    token_url text NOT NULL,
    user_info_url text NOT NULL,
    scopes text[] NOT NULL,
    is_enabled boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_type text NOT NULL,
    user_id uuid,
    client_id uuid,
    actor_id uuid,
    ip_address text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_family_id uuid NOT NULL,
    token_hash text NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    access_token_id uuid,
    previous_token_id uuid,
    scope text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    is_revoked boolean DEFAULT false NOT NULL,
    revoked_at timestamp with time zone,
    revoke_reason text,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version bigint NOT NULL,
    dirty boolean NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    first_name text,
    last_name text,
    is_active boolean DEFAULT true NOT NULL,
    locale character varying(10) DEFAULT 'en-US'::character varying NOT NULL,
    provider text,
    provider_id text,
    provider_data jsonb DEFAULT '{}'::jsonb,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_admin boolean DEFAULT false,
    password_hash text,
    force_password_change boolean DEFAULT false NOT NULL,
    failed_login_attempts integer DEFAULT 0 NOT NULL,
    last_failed_login_at timestamp with time zone,
    locked_until timestamp with time zone
);


--
-- Name: access_tokens access_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_tokens
    ADD CONSTRAINT access_tokens_pkey PRIMARY KEY (id);


--
-- Name: access_tokens access_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_tokens
    ADD CONSTRAINT access_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: authorization_codes authorization_codes_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_codes
    ADD CONSTRAINT authorization_codes_code_key UNIQUE (code);


--
-- Name: authorization_codes authorization_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_codes
    ADD CONSTRAINT authorization_codes_pkey PRIMARY KEY (id);


--
-- Name: clients clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (id);


--
-- Name: oauth_providers oauth_providers_client_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_providers
    ADD CONSTRAINT oauth_providers_client_id_name_key UNIQUE (client_id, name);


--
-- Name: oauth_providers oauth_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_providers
    ADD CONSTRAINT oauth_providers_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: refresh_tokens refresh_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: idx_access_tokens_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_access_tokens_client_id ON public.access_tokens USING btree (client_id);


--
-- Name: idx_access_tokens_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_access_tokens_expires_at ON public.access_tokens USING btree (expires_at);


--
-- Name: idx_access_tokens_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_access_tokens_user_id ON public.access_tokens USING btree (user_id);


--
-- Name: idx_authorization_codes_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_authorization_codes_client_id ON public.authorization_codes USING btree (client_id);


--
-- Name: idx_authorization_codes_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_authorization_codes_expires_at ON public.authorization_codes USING btree (expires_at);


--
-- Name: idx_authorization_codes_provider_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_authorization_codes_provider_id ON public.authorization_codes USING btree (provider_id);


--
-- Name: idx_authorization_codes_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_authorization_codes_user_id ON public.authorization_codes USING btree (user_id);


--
-- Name: idx_clients_is_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_clients_is_active ON public.clients USING btree (is_active);


--
-- Name: idx_oauth_providers_client_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_providers_client_enabled ON public.oauth_providers USING btree (client_id, is_enabled);


--
-- Name: idx_oauth_providers_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_providers_client_id ON public.oauth_providers USING btree (client_id);


--
-- Name: idx_oauth_providers_is_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_providers_is_enabled ON public.oauth_providers USING btree (is_enabled);


--
-- Name: idx_users_is_admin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_is_admin ON public.users USING btree (is_admin);


--
-- Name: idx_users_locked_until; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_locked_until ON public.users USING btree (locked_until);


--
-- Name: users_provider_provider_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_provider_provider_id_key ON public.users USING btree (provider, provider_id);


--
-- Name: idx_audit_log_event_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_event_type ON public.audit_log USING btree (event_type);


--
-- Name: idx_audit_log_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_user_id ON public.audit_log USING btree (user_id);


--
-- Name: idx_audit_log_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_client_id ON public.audit_log USING btree (client_id);


--
-- Name: idx_audit_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_created_at ON public.audit_log USING btree (created_at);


--
-- Name: idx_refresh_tokens_token_family_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_token_family_id ON public.refresh_tokens USING btree (token_family_id);


--
-- Name: idx_refresh_tokens_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_user_id ON public.refresh_tokens USING btree (user_id);


--
-- Name: idx_refresh_tokens_client_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_client_id ON public.refresh_tokens USING btree (client_id);


--
-- Name: idx_refresh_tokens_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_expires_at ON public.refresh_tokens USING btree (expires_at);


--
-- Name: idx_refresh_tokens_access_token_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_refresh_tokens_access_token_id ON public.refresh_tokens USING btree (access_token_id);


--
-- Name: clients set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.clients FOR EACH ROW EXECUTE FUNCTION public.internal_set_updated_at();


--
-- Name: oauth_providers set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.oauth_providers FOR EACH ROW EXECUTE FUNCTION public.internal_set_updated_at();


--
-- Name: users set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER set_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.internal_set_updated_at();


--
-- Name: access_tokens access_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_tokens
    ADD CONSTRAINT access_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: access_tokens access_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_tokens
    ADD CONSTRAINT access_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: authorization_codes authorization_codes_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_codes
    ADD CONSTRAINT authorization_codes_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: authorization_codes authorization_codes_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_codes
    ADD CONSTRAINT authorization_codes_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.oauth_providers(id) ON DELETE CASCADE;


--
-- Name: authorization_codes authorization_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.authorization_codes
    ADD CONSTRAINT authorization_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: clients clients_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.clients
    ADD CONSTRAINT clients_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: oauth_providers oauth_providers_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_providers
    ADD CONSTRAINT oauth_providers_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: refresh_tokens refresh_tokens_access_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_access_token_id_fkey FOREIGN KEY (access_token_id) REFERENCES public.access_tokens(id) ON DELETE SET NULL;


--
-- Name: refresh_tokens refresh_tokens_previous_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_previous_token_id_fkey FOREIGN KEY (previous_token_id) REFERENCES public.refresh_tokens(id) ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--


