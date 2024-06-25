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
          // "domain" is the Google Workspaces domain
          const domain = profile._json.hd;
          const team = await getTeamFromContext(ctx);
          const client = getClientFromContext(ctx);

          // Remove the check for personal Gmail accounts
          /*
          if (!domain && !team) {
            const userExists = await User.count({
              where: { email: profile.email.toLowerCase() },
            });

            if (!userExists) {
              throw GmailAccountCreationError();
            }

            throw TeamDomainRequiredError();
          }
          */

          const subdomain = domain ? slugifyDomain(domain) : "";
          const teamName = subdomain && subdomain.length >= 2 && subdomain.length <= 255 ? capitalize(subdomain) : "My Team";

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
              name: profile.displayName && profile.displayName.length >= 2 && profile.displayName.length <= 255 ? profile.displayName : "Default User",
              language,
              avatarUrl,
            },
            authenticationProvider: {
              name: config.id,
              providerId: domain ?? "",
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

