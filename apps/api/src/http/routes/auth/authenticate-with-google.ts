import axios from 'axios'
import type { FastifyInstance } from 'fastify'
import type { ZodTypeProvider } from 'fastify-type-provider-zod'
import z from 'zod'

import { prisma } from '@/lib/prisma'

import { BadRequestError } from '../_errors/bad-request-error'

export async function authenticateWithGoogle(app: FastifyInstance) {
  app.withTypeProvider<ZodTypeProvider>().post(
    '/sessions/google',
    {
      schema: {
        tags: ['Auth'],
        summary: 'Authenticate with Google',
        body: z.object({
          code: z.string(),
        }),
        response: {
          201: z.object({
            token: z.string(),
          }),
        },
      },
    },

    async (request, reply) => {
      const { code } = request.body

      const CLIENT_ID =
        '1020175485053-phvp7s9pd64otdlh419rfhsd0a15pf06.apps.googleusercontent.com'
      const CLIENT_SECRET = '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'
      const REDIRECT_URI = 'http://localhost:3000/auth/api/callback'

      const payload = {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code: decodeURIComponent(code),
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code',
      }

      // refatorar para o axios
      const googleAuthTokenResponse = await fetch(
        'https://accounts.google.com/o/oauth2/token',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams(payload),
        },
      )

      const googleAuthTokenData = await googleAuthTokenResponse.json()

      const { access_token: googleAccessToken } = z
        .object({
          access_token: z.string(),
          id_token: z.string(),
        })
        .parse(googleAuthTokenData)

      const { data: profile } = await axios.get(
        'https://www.googleapis.com/oauth2/v1/userinfo',
        {
          headers: {
            Authorization: `Bearer ${googleAccessToken}`,
          },
        },
      )

      if (profile.email === null) {
        throw new BadRequestError(
          'Your Google account have an email to authenticate',
        )
      }

      let user = await prisma.user.findUnique({
        where: { email: profile.email },
      })

      if (!user) {
        user = await prisma.user.create({
          data: {
            name: profile.name,
            email: profile.email,
            avatarUrl: profile.picture,
          },
        })
      }

      let account = await prisma.account.findUnique({
        where: {
          provider_userId: {
            provider: 'GOOGLE',
            userId: user.id,
          },
        },
      })

      if (!account) {
        account = await prisma.account.create({
          data: {
            provider: 'GOOGLE',
            providerAccountId: profile.id,
            userId: user.id,
          },
        })
      }

      const token = await reply.jwtSign(
        { sub: user.id },
        { sign: { expiresIn: '7d' } },
      )

      return reply.status(201).send({ token })
    },
  )
}
