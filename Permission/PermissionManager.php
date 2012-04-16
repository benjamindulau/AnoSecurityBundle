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

    public function grantPrivileges(array $privileges, $onType, $onValue, $toType, $toValue)
    {
        switch($toType) {
            case self::TO_USER:
                $identity = $this->getUserSecurityIdentity($toValue);
            break;

            case self::TO_ROLE:
                $identity = $this->getRoleSecurityIdentity($toValue);
            break;

            default:
                throw new \InvalidArgumentException(sprintf('Unexpected value "%s" for $toType', $toType));
        }

        switch($onType) {
            case self::ON_OBJECT:
                $this->doGrantPrivilegesOnObject($privileges, $onValue, $identity);
            break;

            case self::ON_CLASS:
                $this->doGrantPrivilegesOnClass($privileges, $onValue, $identity);
            break;

            default:
                throw new \InvalidArgumentException(sprintf('Unexpected value "%s" for $onType', $onType));
        }
    }

    public function revokePrivileges(array $privileges, $onType, $onValue, $fromType, $fromValue)
    {
        // TODO: Implement revokePrivileges() method.
    }

    /**
     * @param  UserInterface $user
     *
     * @return UserSecurityIdentity
     */
    protected function getUserSecurityIdentity(UserInterface $user)
    {
        // TODO: Dependency to Doctrine here => To be removed as soon as a standard way is implemented in Symfony Security Component
        $securityIdentity = new UserSecurityIdentity($user->getUsername(), ClassUtils::getClass($user));

        return $securityIdentity;
    }

    /**
     * @param  mixed $role
     *
     * @return RoleSecurityIdentity
     */
    protected function getRoleSecurityIdentity($role)
    {
        return new RoleSecurityIdentity($role);
    }

    /**
     * @param array $privileges
     * @param mixed $object
     * @param SecurityIdentityInterface $securityIdentity
     * @throws \InvalidArgumentException
     */
    protected function doGrantPrivilegesOnObject(array $privileges, $object, SecurityIdentityInterface $securityIdentity)
    {
        if (!is_object($object)) {
            throw new \InvalidArgumentException(sprintf('$object must be an instance of an object'));
        }

        // TODO: Dependency to Doctrine here => To be removed as soon as a standard way is implemented in Symfony Security Component
        $objectIdentity = new ObjectIdentity($object->getId(), ClassUtils::getClass($object));
        $acl = $this->loadAcl($objectIdentity);

        // grant
        foreach ($privileges as $privilege) {
            $acl->insertObjectAce($securityIdentity, $privilege);
        }

        $this->aclProvider->updateAcl($acl);
    }

    /**
     * @param array  $privileges
     * @param string $class
     * @param SecurityIdentityInterface $securityIdentity
     */
    protected function doGrantPrivilegesOnClass(array $privileges, $class, SecurityIdentityInterface $securityIdentity)
    {
        $objectIdentity = new ObjectIdentity('class', $class);
        $acl = $this->loadAcl($objectIdentity);

        // grant
        foreach ($privileges as $privilege) {
            $acl->insertClassAce($securityIdentity, $privilege);
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