import RSVP from 'rsvp';
import { isEmpty } from '@ember/utils';
import BaseAuthenticator from './base';
import { run } from '@ember/runloop';

/**
 Authenticator that conforms to OAuth 2
 ([RFC 6749](http://tools.ietf.org/html/rfc6749)), specifically the _"Implicit
 Grant Type"_.

 Use {{#crossLink "OAuth2ImplicitGrantCallbackMixin"}}{{/crossLink}} in your
 OAuth 2.0 redirect route to parse authentication parameters from location
 hash string into an object.

 @class OAuth2ImplicitGrantAuthenticator
 @module ember-simple-auth/authenticators/oauth2-implicit-grant
 @extends BaseAuthenticator
 @public
 */
export default BaseAuthenticator.extend({
  /**
    Sets whether the authenticator automatically refreshes access tokens if the
    server supports it.
    @property refreshAccessTokens
    @type Boolean
    @default true
    @public
  */
  refreshAccessTokens: true,

  /**
    The offset time in milliseconds to refresh the access token. This must
    return a random number. This randomization is needed because in case of
    multiple tabs, we need to prevent the tabs from sending refresh token
    request at the same exact moment.
    __When overriding this property, make sure to mark the overridden property
    as volatile so it will actually have a different value each time it is
    accessed.__
    @property tokenRefreshOffset
    @type Integer
    @default a random number between 5 and 10
    @public
  */
  tokenRefreshOffset: computed(function() {
    const min = 5;
    const max = 10;

    return (Math.floor(Math.random() * (max - min)) + min) * 1000;
  }).volatile(),

  _refreshTokenTimeout: null,
  /**
    Restores the session from a session data object; __will return a resolving
    promise when there is a non-empty `access_token` in the session data__ and
    a rejecting promise otherwise.
    If the server issues
    [expiring access tokens](https://tools.ietf.org/html/rfc6749#section-5.1)
    and there is an expired access token in the session data along with a
    refresh token, the authenticator will try to refresh the access token and
    return a promise that resolves with the new access token if the refresh was
    successful. If there is no refresh token or the token refresh is not
    successful, a rejecting promise will be returned.
    @method restore
    @param {Object} data The data to restore the session from
    @return {Ember.RSVP.Promise} A promise that when it resolves results in the session becoming or remaining authenticated
    @public
  */
  restore(data) {
    return new RSVP.Promise((resolve, reject) => {
      const now = (new Date()).getTime();
      const refreshAccessTokens = this.get('refreshAccessTokens');
      if (!isEmpty(data['expires_at']) && data['expires_at'] < now) {
        if (refreshAccessTokens) {
          this._refreshAccessToken(data['expires_in'], data['refresh_token']).then(resolve, reject);
        } else {
          reject();
        }
      } else {
        if (!this._validate(data)) {
          reject();
        } else {
          this._scheduleAccessTokenRefresh(data['expires_in'], data['expires_at'], data['refresh_token']);
          resolve(data);
        }
      }
    });
  },

  /**
   Authenticates the session using the specified location `hash`
   (see https://tools.ietf.org/html/rfc6749#section-4.2.2).

   __If the access token is valid and thus authentication succeeds, a promise that
   resolves with the access token is returned__, otherwise a promise that rejects
   with the error code as returned by the server is returned
   (see https://tools.ietf.org/html/rfc6749#section-4.2.2.1).

   @method authenticate
   @param {Object} hash The location hash
   @return {Ember.RSVP.Promise} A promise that when it resolves results in the session becoming authenticated
   @public
   */
  authenticate(hash) {
    return new RSVP.Promise((resolve, reject) => {
      if (hash.error) {
        reject(hash.error);
      } else if (!this._validateData(hash)) {
        reject('Invalid auth params - "access_token" missing.');
      } else {
          const expiresAt = this._absolutizeExpirationTime(hash['expires_in']);
          this._scheduleAccessTokenRefresh(hash['expires_in'], expiresAt, hash['refresh_token']);
          if (!isEmpty(expiresAt)) {
            hash = assign(hash, { 'expires_at': expiresAt });
          }        
          resolve(hash);
      }
    });
  },
  
  _absolutizeExpirationTime(expiresIn) {
    if (!isEmpty(expiresIn)) {
      return new Date((new Date().getTime()) + expiresIn * 1000).getTime();
    }
  },
  
  _scheduleAccessTokenRefresh(expiresIn, expiresAt, refreshToken) {
    const refreshAccessTokens = this.get('refreshAccessTokens');
    if (refreshAccessTokens) {
      const now = (new Date()).getTime();
      if (isEmpty(expiresAt) && !isEmpty(expiresIn)) {
        expiresAt = new Date(now + expiresIn * 1000).getTime();
      }
      const offset = this.get('tokenRefreshOffset');
      if (!isEmpty(refreshToken) && !isEmpty(expiresAt) && expiresAt > now - offset) {
        run.cancel(this._refreshTokenTimeout);
        delete this._refreshTokenTimeout;
        if (!Ember.testing) {
          this._refreshTokenTimeout = run.later(this, this._refreshAccessToken, expiresIn, refreshToken, expiresAt - now - offset);
        }
      }
    }
  },

  _refreshAccessToken(expiresIn, refreshToken) {
    const data = { 'grant_type': 'refresh_token', 'refresh_token': refreshToken };
    const serverTokenEndpoint = this.get('serverTokenEndpoint');
    return new RSVP.Promise((resolve, reject) => {
      this.makeRequest(serverTokenEndpoint, data).then((response) => {
        run(() => {
          expiresIn = response['expires_in'] || expiresIn;
          refreshToken = response['refresh_token'] || refreshToken;
          const expiresAt = this._absolutizeExpirationTime(expiresIn);
          const data = assign(response, { 'expires_in': expiresIn, 'expires_at': expiresAt, 'refresh_token': refreshToken });
          this._scheduleAccessTokenRefresh(expiresIn, null, refreshToken);
          this.trigger('sessionDataUpdated', data);
          resolve(data);
        });
      }, (response) => {
        warn(`Access token could not be refreshed - server responded with ${response.responseJSON}.`, false, { id: 'ember-simple-auth.failedOAuth2TokenRefresh' });
        reject();
      });
    });
  },

  /**
   This method simply returns a resolving promise.

   @method invalidate
   @return {Ember.RSVP.Promise} A promise that when it resolves results in the session being invalidated
   @public
   */
  invalidate() {
    return RSVP.Promise.resolve();
  },

  _validateData(data) {
    // see https://tools.ietf.org/html/rfc6749#section-4.2.2

    return !isEmpty(data) && !isEmpty(data.access_token);
  }
});
