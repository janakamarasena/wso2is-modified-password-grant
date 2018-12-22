/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.sample.identity.oauth2.grant.password;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;

/**
 * Modified version of password grant type to invalidated current access token and refresh token and issue ne2w tokens.
 */
public class ModifiedPasswordGrant extends PasswordGrantHandler {

    private static Log log = LogFactory.getLog(ModifiedPasswordGrant.class);
    private boolean isHashDisabled = OAuth2Util.isHashDisabled();

    @Override
    public OAuth2AccessTokenRespDTO issue(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        String scope = OAuth2Util.buildScopeString(tokReqMsgCtx.getScope());
        String consumerKey = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();
        String authorizedUser = tokReqMsgCtx.getAuthorizedUser().toString();

        synchronized ((consumerKey + ":" + authorizedUser + ":" + scope).intern()) {
            AccessTokenDO existingTokenBean = null;
            if (isHashDisabled) {
                existingTokenBean = getExistingToken(tokReqMsgCtx,
                        getOAuthCacheKey(scope, consumerKey, authorizedUser));
            }
            // Return a new access token in each request when JWTTokenIssuer is used.
            if (accessTokenNotRenewedPerRequest(tokReqMsgCtx)) {
                if (existingTokenBean != null) {
                    revokeExistingToken(tokReqMsgCtx, existingTokenBean);
                }
            }
            return super.issue(tokReqMsgCtx);
        }
    }

    private void revokeExistingToken(OAuthTokenReqMessageContext tokReqMsgCtx, AccessTokenDO existingTokenBean)
            throws IdentityOAuth2Exception {

        OAuthRevocationRequestDTO revocationRequestDTO = new OAuthRevocationRequestDTO();
        OAuthClientAuthnContext oAuthClientAuthnContext = tokReqMsgCtx.getOauth2AccessTokenReqDTO()
                .getoAuthClientAuthnContext();

        String token = existingTokenBean.getAccessToken();
        if (StringUtils.isEmpty(token)) {
            log.error("Access token not available.");
        }

        revocationRequestDTO.setToken(token);
        revocationRequestDTO.setOauthClientAuthnContext(oAuthClientAuthnContext);
        revocationRequestDTO.setConsumerKey(oAuthClientAuthnContext.getClientId());

        OAuthRevocationResponseDTO revocationResponseDTO = getOauth2Service()
                .revokeTokenByOAuthClient(revocationRequestDTO);

        if (revocationResponseDTO.isError()) {
            String msg = "Error while revoking tokens: " + revocationResponseDTO.getErrorMsg();
            log.error(msg);
            throw new IdentityOAuth2Exception(msg);
        }
    }

    private AccessTokenDO getExistingToken(OAuthTokenReqMessageContext tokenMsgCtx, OAuthCacheKey cacheKey)
            throws IdentityOAuth2Exception {

        AccessTokenDO existingToken = null;
        OAuth2AccessTokenReqDTO tokenReq = tokenMsgCtx.getOauth2AccessTokenReqDTO();
        String scope = OAuth2Util.buildScopeString(tokenMsgCtx.getScope());

        if (cacheEnabled) {
            existingToken = getExistingTokenFromCache(cacheKey, tokenReq.getClientId(),
                    tokenMsgCtx.getAuthorizedUser().toString(), scope);
        }

        if (existingToken == null) {
            existingToken = getExistingTokenFromDB(tokenMsgCtx, tokenReq, scope, cacheKey);
        }
        return existingToken;
    }

    private OAuth2Service getOauth2Service() {

        return (OAuth2Service) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(OAuth2Service.class, null);
    }

    private OAuthCacheKey getOAuthCacheKey(String scope, String consumerKey, String authorizedUser) {

        String cacheKeyString = OAuth2Util.buildCacheKeyStringForToken(consumerKey, scope, authorizedUser);
        return new OAuthCacheKey(cacheKeyString);
    }

    private AccessTokenDO getExistingTokenFromCache(OAuthCacheKey cacheKey, String consumerKey, String authorizedUser,
                                                    String scope) throws IdentityOAuth2Exception {

        AccessTokenDO existingToken = null;
        CacheEntry cacheEntry = oauthCache.getValueFromCache(cacheKey);
        if (cacheEntry instanceof AccessTokenDO) {
            existingToken = (AccessTokenDO) cacheEntry;
            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Retrieved active access token(hashed): " + DigestUtils.sha256Hex
                        (existingToken.getAccessToken()) + " in the state: " + existingToken.getTokenState() +
                        " for client Id " + consumerKey + ", user " + authorizedUser +
                        " and scope " + scope + " from cache");
            }
            if (getAccessTokenExpiryTimeMillis(existingToken) == 0) {
                // Token is expired. Clear it from cache.
                removeFromCache(cacheKey, consumerKey, existingToken);
            }
        }
        return existingToken;
    }

    private AccessTokenDO getExistingTokenFromDB(OAuthTokenReqMessageContext tokenMsgCtx,
                                                 OAuth2AccessTokenReqDTO tokenReq, String scope, OAuthCacheKey cacheKey)
            throws IdentityOAuth2Exception {

        AccessTokenDO existingToken = OAuthTokenPersistenceFactory.getInstance()
                .getAccessTokenDAO().getLatestAccessToken(tokenReq.getClientId(), tokenMsgCtx.getAuthorizedUser(),
                        getUserStoreDomain(tokenMsgCtx.getAuthorizedUser()), scope, false);
        if (existingToken != null) {
            if (log.isDebugEnabled()) {
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Retrieved latest access token(hashed): " + DigestUtils.sha256Hex
                            (existingToken.getAccessToken()) + " in the state: " + existingToken.getTokenState() +
                            " for client Id: " + tokenReq.getClientId() + " user: " + tokenMsgCtx.getAuthorizedUser() +
                            " and scope: " + scope + " from db");
                } else {
                    log.debug("Retrieved latest access token for client Id: " + tokenReq.getClientId() + " user: " +
                            tokenMsgCtx.getAuthorizedUser() + " and scope: " + scope + " from db");
                }
            }
            long expireTime = getAccessTokenExpiryTimeMillis(existingToken);
            if (TOKEN_STATE_ACTIVE.equals(existingToken.getTokenState()) &&
                    expireTime != 0) {
                // Active token retrieved from db, adding to cache if cacheEnabled
                addTokenToCache(cacheKey, existingToken);
            }
        }
        return existingToken;
    }

    /**
     * Returns access token expiry time in milliseconds for given access token.
     *
     * @param existingAccessTokenDO
     * @return
     * @throws IdentityOAuth2Exception
     */
    private long getAccessTokenExpiryTimeMillis(AccessTokenDO existingAccessTokenDO) throws IdentityOAuth2Exception {

        long expireTimeMillis;
        if (issueRefreshToken()) {
            // Consider both access and refresh expiry time
            expireTimeMillis = OAuth2Util.getTokenExpireTimeMillis(existingAccessTokenDO);
        } else {
            // Consider only access token expiry time
            expireTimeMillis = OAuth2Util.getAccessTokenExpireMillis(existingAccessTokenDO);
        }
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                if (expireTimeMillis > 0) {
                    log.debug("Access Token(hashed): " + DigestUtils.sha256Hex(existingAccessTokenDO
                            .getAccessToken()) + " is still valid. Remaining time: " +
                            expireTimeMillis + "ms");
                } else {
                    log.debug("Infinite lifetime Access Token(hashed) "
                            + DigestUtils.sha256Hex(existingAccessTokenDO
                            .getAccessToken()) + " found");
                }
            } else {
                if (expireTimeMillis > 0) {
                    log.debug("Valid access token is found in cache for client: " +
                            existingAccessTokenDO.getConsumerKey() + ". Remaining time: " + expireTimeMillis + "ms");
                } else {
                    log.debug("Infinite lifetime Access Token found in cache for client: " +
                            existingAccessTokenDO.getConsumerKey());
                }
            }
        }
        return expireTimeMillis;
    }

    private void addTokenToCache(OAuthCacheKey cacheKey, AccessTokenDO existingAccessTokenDO) {

        if (cacheEnabled) {
            oauthCache.addToCache(cacheKey, existingAccessTokenDO);
            // Adding AccessTokenDO to improve validation performance
            OAuthCacheKey accessTokenCacheKey = new OAuthCacheKey(existingAccessTokenDO.getAccessToken());
            oauthCache.addToCache(accessTokenCacheKey, existingAccessTokenDO);
            if (log.isDebugEnabled()) {
                log.debug("Access Token info was added to the cache for the cache key : " +
                        cacheKey.getCacheKeyString());
                if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                    log.debug("Access token was added to OAuthCache for cache key : " + accessTokenCacheKey
                            .getCacheKeyString());
                }
            }
        }
    }

    private void removeFromCache(OAuthCacheKey cacheKey, String consumerKey, AccessTokenDO existingAccessTokenDO) {

        oauthCache.clearCacheEntry(cacheKey);
        if (log.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                log.debug("Access token(hashed) " + DigestUtils.sha256Hex(existingAccessTokenDO
                        .getAccessToken()) + " is expired. Therefore cleared it from cache and marked" +
                        " it as expired in database");
            } else {
                log.debug("Existing access token for client: " + consumerKey + " is expired. " +
                        "Therefore cleared it from cache and marked it as expired in database");
            }
        }
    }

    private boolean accessTokenNotRenewedPerRequest(OAuthTokenReqMessageContext tokReqMsgCtx) {

        boolean isRenew1 = oauthIssuerImpl.renewAccessTokenPerRequest();
        boolean isRenew2 = oauthIssuerImpl.renewAccessTokenPerRequest(tokReqMsgCtx);
        if (log.isDebugEnabled()) {
            log.debug("Enable Access Token renew per request: " + isRenew1);
            log.debug("Enable Access Token renew per request considering OAuthTokenReqMessageContext: " + isRenew1);
        }

        if (isRenew1 || isRenew2) {
            return false;
        }
        return true;
    }
}
