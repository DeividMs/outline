import passport from "@outlinewiki/koa-passport";
import type { Context } from "koa";
import Router from "koa-router";
import capitalize from "lodash/capitalize";
import { Profile } from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import { languages } from "@shared/i18n";
import { slugifyDomain } from "@shared/utils/domains";
import accountProvisioner from "@server/commands/accountProvisioner";
import passportMiddleware from "@server/middlewares/passport";
import { User } from "@server/models";
import { AuthenticationResult } from "@server/types";
import {
  StateStore,
  getTeamFromContext,
  getClientFromContext,
} from "@server/utils/passport";
import config from "../../plugin.json";
import env from "../env";

const router = new Router();

const scopes = [
  "https://www.googleapis.com/auth/userinfo.profile",
  "https://www.googleapis.com/auth/userinfo.email",
];

type GoogleProfile = Profile & {
  email: string;
  picture: string;
  _json: {
    hd?: string;
    locale?: string;
  };
};

if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: env.GOOGLE_CLIENT_ID,
        clientSecret: env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${env.URL}/auth/${config.id}.callback`,
        passReqToCallback: true,
        // @ts-expect-error StateStore
        store: new StateStore(),
        scope: scopes,
      },
      async function (
        ctx: Context,
        accessToken: string,
        refreshToken: string,
        params: { expires_in: number },
        profile: GoogleProfile,
        done: (
          err: Error | null,
          user: User | null,
          result?: AuthenticationResult
        ) => void
      ) {
        try {
          // Definir `domain` vazio para evitar bloqueios
          const domain = ""; // Remove qualquer dependência de domínio
          const subdomain = ""; // Não configurar subdomínio para e-mails pessoais
          const teamName = "My Team"; // Nome padrão para o time

          const avatarUrl = profile.picture.replace("=s96-c", "=s128-c");
          const locale = profile._json.locale;
          const language = locale
            ? languages.find((l) => l.startsWith(locale))
            : undefined;

          const result = await accountProvisioner({
            ip: ctx.ip,
            team: {
              teamId: team?.id,
              name: teamName,
              domain,
              subdomain,
            },
            user: {
              email: profile.email,
              name:
                profile.displayName &&
                profile.displayName.length >= 2 &&
                profile.displayName.length <= 255
                  ? profile.displayName
                  : "Default User",
              language,
              avatarUrl,
            },
            authenticationProvider: {
              name: config.id,
              providerId: "", // Remove qualquer validação do domínio aqui também
            },
            authentication: {
              providerId: profile.id,
              accessToken,
              refreshToken,
              expiresIn: params.expires_in,
              scopes,
            },
          });

          return done(null, result.user, { ...result, client });
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );

  router.get(
    config.id,
    passport.authenticate(config.id, {
      accessType: "offline",
      prompt: "select_account consent",
    })
  );
  router.get(`${config.id}.callback`, passportMiddleware(config.id));
}

export default router;
