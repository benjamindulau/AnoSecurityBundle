<?php

/**
 * This file is part of the AnoSecurityBundle
 *
 * (c) anonymation <contact@anonymation.com>
 *
 */

namespace Ano\Bundle\SecurityBundle\Permission;

use
    Symfony\Component\Security\Core\User\UserInterface,
    Symfony\Component\Security\Acl\Model\MutableAclProviderInterface,
    Symfony\Component\Security\Acl\Permission\MaskBuilder,
    Symfony\Component\Security\Acl\Model\SecurityIdentityInterface,
    Symfony\Component\Security\Acl\Model\ObjectIdentityInterface,
    Symfony\Component\Security\Acl\Domain\UserSecurityIdentity,
    Symfony\Component\Security\Acl\Domain\ObjectIdentity,
    Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity,
    Symfony\Component\Security\Acl\Exception\AclAlreadyExistsException,
    Doctrine\Common\Util\ClassUtils
;

/**
 * Implementation of AclManagerInterface
 * an abstraction of common Symfony2's ACLs/ACEs related operations
 *
 * @author Benjamin Dulau <benjamin.dulau@anonymation.com>
 */
class PermissionManager implements PermissionManagerInterface
{
    /** @var MutableAclProviderInterface */
    protected $aclProvider;

    public function __construct(MutableAclProviderInterface $aclProvider)
    {
        $this->aclProvider = $aclProvider;
    }

    public function grantPrivileges($privileges, $onType, $onValue, $toType, $toValue)
    {
        if (!is_array($privileges)) {
            $privileges = array($privileges);
        }

        switch($toType) {
            case self::TO_USER:
                $identities = $this->getUserSecurityIdentity($toValue);
            break;

            case self::TO_ROLE:
                $identities = $this->getRoleSecurityIdentity($toValue);
            break;

            default:
                throw new \InvalidArgumentException(sprintf('Unexpected value "%s" for $toType', $toType));
        }

        switch($onType) {
            case self::ON_OBJECT:
                $this->doGrantPrivilegesOnObject($privileges, $onValue, $identities);
            break;

            case self::ON_CLASS:
                $this->doGrantPrivilegesOnClass($privileges, $onValue, $identities);
            break;

            default:
                throw new \InvalidArgumentException(sprintf('Unexpected value "%s" for $onType', $onType));
        }
    }

    public function revokePrivileges($privileges, $onType, $onValue, $fromType, $fromValue)
    {
        if (!is_array($privileges)) {
            $privileges = array($privileges);
        }

        switch($fromType) {
            case self::FROM_USER:
                $identities = $this->getUserSecurityIdentity($fromValue);
            break;

            case self::FROM_ROLE:
                $identities = $this->getRoleSecurityIdentity($fromValue);
            break;

            default:
                throw new \InvalidArgumentException(sprintf('Unexpected value "%s" for $fromType', $fromType));
        }

        switch($onType) {
            case self::ON_OBJECT:
                $this->doRevokePrivilegesOnObject($privileges, $onValue, $identities);
            break;

            case self::ON_CLASS:
                $this->doRevokePrivilegesOnClass($privileges, $onValue, $identities);
            break;

            default:
                throw new \InvalidArgumentException(sprintf('Unexpected value "%s" for $onType', $onType));
        }
    }

    /**
     * @param  UserInterface[] $users
     *
     * @return UserSecurityIdentity[]
     */
    protected function getUserSecurityIdentity($users)
    {
        if (!is_array($users)) {
            $users = array($users);
        }

        $identities = array();
        foreach($users as $user) {
            // TODO: Dependency to Doctrine here => To be removed as soon as a standard way is implemented in Symfony Security Component
            $identities[] = new UserSecurityIdentity($user->getUsername(), ClassUtils::getClass($user));
        }

        return $identities;
    }

    /**
     * @param  mixed $roles
     *
     * @return RoleSecurityIdentity[]
     */
    protected function getRoleSecurityIdentity($roles)
    {
        if (!is_array($roles)) {
            $roles = array($roles);
        }

        $identities = array();
        foreach($roles as $role) {
            // TODO: Dependency to Doctrine here => To be removed as soon as a standard way is implemented in Symfony Security Component
            $identities[] = new RoleSecurityIdentity($role);
        }

        return $identities;
    }

    /**
     * @param array $privileges
     * @param mixed $objects
     * @param array|SecurityIdentityInterface[] $securityIdentities
     * @throws \DomainException
     * @throws \InvalidArgumentException
     */
    protected function doGrantPrivilegesOnObject(array $privileges, $objects, array $securityIdentities)
    {
        if (!is_array($objects)) {
            $objects = array($objects);
        }

        foreach($objects as $object) {
            if (!is_object($object)) {
                throw new \InvalidArgumentException(sprintf('$object must be an instance of an object'));
            }

            if (!method_exists($object, 'getId')) {
                throw new \DomainException(sprintf('$object must have a method named "getId".'));
            }

            // TODO: Dependency to Doctrine here => To be removed as soon as a standard way is implemented in Symfony Security Component
            $oid = new ObjectIdentity($object->getId(), ClassUtils::getClass($object));
            $acl = $this->loadAcl($oid);

            // grant
            foreach ($privileges as $privilege) {
                foreach($securityIdentities as $securityIdentity) {
                    $acl->insertObjectAce($securityIdentity, $privilege);
                }
            }

            $this->aclProvider->updateAcl($acl);
        }
    }

    /**
     * @param array  $privileges
     * @param string $class
     * @param SecurityIdentityInterface[] $securityIdentities
     */
    protected function doGrantPrivilegesOnClass(array $privileges, $class, array $securityIdentities)
    {
        $objectIdentity = new ObjectIdentity('class', $class);
        $acl = $this->loadAcl($objectIdentity);

        // grant
        foreach ($privileges as $privilege) {
            foreach($securityIdentities as $securityIdentity) {
                $acl->insertClassAce($securityIdentity, $privilege);
            }
        }

        $this->aclProvider->updateAcl($acl);
    }

    /**
     * @param array $privileges
     * @param mixed $objects
     * @param SecurityIdentityInterface[] $securityIdentities
     * @throws \InvalidArgumentException
     */
    protected function doRevokePrivilegesOnObject(array $privileges, $objects, array $securityIdentities)
    {
        if (!is_array($objects)) {
            $objects = array($objects);
        }

        foreach($objects as $object) {
            if (!is_object($object)) {
                throw new \InvalidArgumentException(sprintf('$object must be an instance of an object'));
            }

            // TODO: Dependency to Doctrine here => To be removed as soon as a standard way is implemented in Symfony Security Component
            $oid = new ObjectIdentity($object->getId(), ClassUtils::getClass($object));
            $acl = $this->loadAcl($oid);

            // revoke
            $aces = $acl->getObjectAces();
            $forCount = count($aces) - 1;
            for ($i = $forCount; $i >= 0; $i--) {
                foreach ($privileges as $privilege) {
                    foreach($securityIdentities as $securityIdentity) {
                        if ($securityIdentity == $aces[$i]->getSecurityIdentity() && $aces[$i]->getMask() == $privilege) {
                            $acl->deleteObjectAce($i);
                        }
                    }
                }
            }

            $this->aclProvider->updateAcl($acl);
        }
    }

    /**
     * @param array  $privileges
     * @param string $class
     * @param SecurityIdentityInterface[] $securityIdentities
     */
    protected function doRevokePrivilegesOnClass(array $privileges, $class, array $securityIdentities)
    {
        $objectIdentity = new ObjectIdentity('class', $class);
        $acl = $this->loadAcl($objectIdentity);

        // revoke
        $aces = $acl->getClassAces();
        $forCount = count($aces) - 1;
        for ($i = $forCount; $i >= 0; $i--) {
            foreach ($privileges as $privilege) {
                foreach($securityIdentities as $securityIdentity) {
                    if ($securityIdentity == $aces[$i]->getSecurityIdentity() && $aces[$i]->getMask() == $privilege) {
                        $acl->deleteClassAce($i);
                    }
                }
            }
        }

        $this->aclProvider->updateAcl($acl);
    }

    /**
     * @param ObjectIdentityInterface $identity
     *
     * @return \Symfony\Component\Security\Acl\Model\MutableAclInterface
     * @throws AclAlreadyExistsException
     */
    protected function loadAcl(ObjectIdentityInterface $identity)
    {
        try {
            $acl = $this->aclProvider->createAcl($identity);
        } catch(AclAlreadyExistsException $e) {
            // Get Acl if already exists
            $acl = $this->aclProvider->findAcl($identity);
        } catch(\Exception $e) {
            throw $e;
        }

        return $acl;
    }

}