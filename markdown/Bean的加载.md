# Bean的加载
上面几章完成了读取配置文件并且对标签进行解析与注册的工作。现在我们进入到加载bean的过程中。在这里，bean加载是以`Beinsert beinsert = (Beinsert) bf.getBean("beinsert");`为入口。加载的过程是在AbstractBeanFactory中进行。
## 1. 重要类的介绍
### FactoryBean
当需要实例化的bean的实例化过程比较复杂时，Spring允许用户通过实现FactoryBean来自定义实例化bean的逻辑。FactoryBean接口定义如下。当Spring配置文件中配置的bean的class属性为一个FactoryBean则其取出的bean不是该FactoryBean，而是该FactoryBean调用getObject方法后返回的结果。使用时，在调用`getBean（"beanName"）;`时，如果希望获得的是FactoryBean对象，则方法中的beanName前需要加上“&”前缀。如果不加“&”前缀，则返回的是FactoryBean调用getObject的返回值。
```java
package org.springframework.beans.factory;

public interface FactoryBean<T> {
	T getObject() throws Exception;
	Class<?> getObjectType();
	boolean isSingleton();

}
```
## 2. bean加载过程
我们首先进入到getBean方法中查看一下Bean加载的大致过程：
```java
	public Object getBean(String name) throws BeansException {
		return doGetBean(name, null, null, false);
	}
    @Override
	public <T> T getBean(String name, Class<T> requiredType) throws BeansException {
		return doGetBean(name, requiredType, null, false);
	}
```
```java
protected <T> T doGetBean(
			final String name, final Class<T> requiredType, final Object[] args, boolean typeCheckOnly)
			throws BeansException {
		//对传入的bean的名字进行处理
		final String beanName = transformedBeanName(name);
		Object bean;

		// 检查缓存中是否存在已经解析了的单例
		Object sharedInstance = getSingleton(beanName);
		if (sharedInstance != null && args == null) {
			if (logger.isDebugEnabled()) {
				if (isSingletonCurrentlyInCreation(beanName)) {
					logger.debug("Returning eagerly cached instance of singleton bean '" + beanName +
							"' that is not fully initialized yet - a consequence of a circular reference");
				}
				else {
					logger.debug("Returning cached instance of singleton bean '" + beanName + "'");
				}
			}
            //返回对应的实例
			bean = getObjectForBeanInstance(sharedInstance, name, beanName, null);
		}

		else {
			// 如果是原型模式并且造成了循环依赖则抛出异常
			if (isPrototypeCurrentlyInCreation(beanName)) {
				throw new BeanCurrentlyInCreationException(beanName);
			}

			// 检查bean是否已经存在在该beanFactory中
			BeanFactory parentBeanFactory = getParentBeanFactory();
			if (parentBeanFactory != null && !containsBeanDefinition(beanName)) {
				// Not found -> check parent.
				String nameToLookup = originalBeanName(name);
				if (args != null) {
					// Delegation to parent with explicit args.
					return (T) parentBeanFactory.getBean(nameToLookup, args);
				}
				else {
					// No args -> delegate to standard getBean method.
					return parentBeanFactory.getBean(nameToLookup, requiredType);
				}
			}

			if (!typeCheckOnly) {
				markBeanAsCreated(beanName);
			}

			try {
				final RootBeanDefinition mbd = getMergedLocalBeanDefinition(beanName);
				checkMergedBeanDefinition(mbd, beanName, args);

				// Guarantee initialization of beans that the current bean depends on.
				String[] dependsOn = mbd.getDependsOn();
				if (dependsOn != null) {
					for (String dependsOnBean : dependsOn) {
						if (isDependent(beanName, dependsOnBean)) {
							throw new BeanCreationException(mbd.getResourceDescription(), beanName,
									"Circular depends-on relationship between '" + beanName + "' and '" + dependsOnBean + "'");
						}
						registerDependentBean(dependsOnBean, beanName);
						getBean(dependsOnBean);
					}
				}

				// Create bean instance.
				if (mbd.isSingleton()) {
					sharedInstance = getSingleton(beanName, new ObjectFactory<Object>() {
						@Override
						public Object getObject() throws BeansException {
							try {
								return createBean(beanName, mbd, args);
							}
							catch (BeansException ex) {
								// Explicitly remove instance from singleton cache: It might have been put there
								// eagerly by the creation process, to allow for circular reference resolution.
								// Also remove any beans that received a temporary reference to the bean.
								destroySingleton(beanName);
								throw ex;
							}
						}
					});
					bean = getObjectForBeanInstance(sharedInstance, name, beanName, mbd);
				}

				else if (mbd.isPrototype()) {
					// It's a prototype -> create a new instance.
					Object prototypeInstance = null;
					try {
						beforePrototypeCreation(beanName);
						prototypeInstance = createBean(beanName, mbd, args);
					}
					finally {
						afterPrototypeCreation(beanName);
					}
					bean = getObjectForBeanInstance(prototypeInstance, name, beanName, mbd);
				}

				else {
					String scopeName = mbd.getScope();
					final Scope scope = this.scopes.get(scopeName);
					if (scope == null) {
						throw new IllegalStateException("No Scope registered for scope '" + scopeName + "'");
					}
					try {
						Object scopedInstance = scope.get(beanName, new ObjectFactory<Object>() {
							@Override
							public Object getObject() throws BeansException {
								beforePrototypeCreation(beanName);
								try {
									return createBean(beanName, mbd, args);
								}
								finally {
									afterPrototypeCreation(beanName);
								}
							}
						});
						bean = getObjectForBeanInstance(scopedInstance, name, beanName, mbd);
					}
					catch (IllegalStateException ex) {
						throw new BeanCreationException(beanName,
								"Scope '" + scopeName + "' is not active for the current thread; " +
								"consider defining a scoped proxy for this bean if you intend to refer to it from a singleton",
								ex);
					}
				}
			}
			catch (BeansException ex) {
				cleanupAfterBeanCreationFailure(beanName);
				throw ex;
			}
		}

		// Check if required type matches the type of the actual bean instance.
		if (requiredType != null && bean != null && !requiredType.isAssignableFrom(bean.getClass())) {
			try {
				return getTypeConverter().convertIfNecessary(bean, requiredType);
			}
			catch (TypeMismatchException ex) {
				if (logger.isDebugEnabled()) {
					logger.debug("Failed to convert bean '" + name + "' to required type [" +
							ClassUtils.getQualifiedName(requiredType) + "]", ex);
				}
				throw new BeanNotOfRequiredTypeException(name, requiredType, bean.getClass());
			}
		}
		return (T) bean;
	}
```
根据其大致的加载过程做出的时序图如下：
## 2.1 从缓存中获取singleton的bean
在Spring中，scope为singleton的bean只会创建一次，后面再使用getBean从容器中取出的bean都是同一个。所以加载bean时，首先尝试从缓存中加载。我们进入到getSingleton方法中查看其过程。要说明的是DefaultSingletonBeanRegistry所持有的几个map中：
- singletonObjects表示BeanName与bean实例的关系；
- earlySingletonObjects表示BeanName与bean实例的关系，但是当bean还在创建过程中就已经可以获取了；
- singletonFactories表示BeanName与创建Bean的工厂之间的关系。

可以看到，首先尝试从singletonObjects缓存中获取实例，当不存在时先检查bean是否正在被加载，如果不是就检查是否需要被提前初始化，如果需要就调用factory的getObject进行创建，然后存放到缓存中。

```java
@Override
	public Object getSingleton(String beanName) {
    	//默认为开启早期依赖
		return getSingleton(beanName, true);
	}

protected Object getSingleton(String beanName, boolean allowEarlyReference) {
		//尝试从缓存中获取实例
		Object singletonObject = this.singletonObjects.get(beanName);
        //当缓存中不存在并且被标记为需要立即创建
		if (singletonObject == null && isSingletonCurrentlyInCreation(beanName)) {
        	//锁定singletonObjects来进行创建
			synchronized (this.singletonObjects) {
            	//再次检查是否此bean是否正在加载
				singletonObject = this.earlySingletonObjects.get(beanName);
				if (singletonObject == null && allowEarlyReference) {
                	//检查是否需要需要提前初始化
					ObjectFactory<?> singletonFactory = this.singletonFactories.get(beanName);
					if (singletonFactory != null) {
                    	//调用getObject方法
						singletonObject = singletonFactory.getObject();
                        //记录在earlySingletonObjects缓存中，记录后删除其工厂
						this.earlySingletonObjects.put(beanName, singletonObject);
						this.singletonFactories.remove(beanName);
					}
				}
			}
		}
		return (singletonObject != NULL_OBJECT ? singletonObject : null);
	}
```
## 2.2 从bean实例中获取对象
通过缓存或者根据scope获得的bean都只是初始状态的bean，还需要在getObjectForBeanInstance方法中进行进一步的加工处理才能得到最终我们想要的bean。在该方法中，首先对bean进行了校验，对不是FactoryBean的或者要求直接返回FactoryBean的不做处理直接返回。最后委派给getObjectFromFactoryBean方法对FactoryBean进行解析。
```java
protected Object getObjectForBeanInstance(
			Object beanInstance, String name, String beanName, RootBeanDefinition mbd) {

		// 当指定的bean要求是FactoryBean的而beanInstance不是则抛出异常
		if (BeanFactoryUtils.isFactoryDereference(name) && !(beanInstance instanceof FactoryBean)) {
			throw new BeanIsNotAFactoryException(transformedBeanName(name), beanInstance.getClass());
		}

		//当不是FactoryBean或者要求直接返回FactoryBean时就直接返回
		if (!(beanInstance instanceof FactoryBean) || BeanFactoryUtils.isFactoryDereference(name)) {
			return beanInstance;
		}
		
		Object object = null;
		if (mbd == null) {
			//尝试从FactoryBean的缓存中获取bean
        	object = getCachedObjectForFactoryBean(beanName);
		}
		if (object == null) {
			// 因为不是FactoryBean的在上面已经返回，所以这里可以进行强制类型转换
			FactoryBean<?> factory = (FactoryBean<?>) beanInstance;
			// 检测已加载的类中是否包含了beanName
			if (mbd == null && containsBeanDefinition(beanName)) {
            	//将储存了XML配置文件的GernericBeanDefinition转换为RootBeanDefinition
				mbd = getMergedLocalBeanDefinition(beanName);
			}
            //判断是否是用户定义的而不是程序本身定义的
			boolean synthetic = (mbd != null && mbd.isSynthetic());
            //将从FactoryBean中解析出bean的工作进行委托
			object = getObjectFromFactoryBean(factory, beanName, !synthetic);
		}
		return object;
	}

```
进入到getObjectFromFactoryBean方法中，在该方法中，首先检查其是否为单例模式，如果是则首先在缓存中取来保证全局唯一，没有才调用doGetObjectFromFactoryBean，非单例模式则直接调用。最后将解析的bean存放到缓存中。除此之外，调用解析后会调用postProcessObjectFromFactoryBean方法，这是调用ObjectFactory的后处理器，实际开发中可以利用这个特性，这个方法在这里不进行分析，后面再进行分析。
```java
protected Object getObjectFromFactoryBean(FactoryBean<?> factory, String beanName, boolean shouldPostProcess) {
		if (factory.isSingleton() && containsSingleton(beanName)) {
        	//如果是单例模式
			synchronized (getSingletonMutex()) {
            	//首先尝试从缓存中获取
				Object object = this.factoryBeanObjectCache.get(beanName);
				if (object == null) {
                	//缓存中没有就调用doGetObjectFromFactoryBean获取
					object = doGetObjectFromFactoryBean(factory, beanName);
                    //检查缓存中是否存在
					Object alreadyThere = this.factoryBeanObjectCache.get(beanName);
					if (alreadyThere != null) {
						object = alreadyThere;
					}
					else {
						if (object != null && shouldPostProcess) {
							try {
                            	//该方法是调用ObjectFactory的后处理器
								object = postProcessObjectFromFactoryBean(object, beanName);
							}
							catch (Throwable ex) {
								throw new BeanCreationException(beanName,
										"Post-processing of FactoryBean's singleton object failed", ex);
							}
						}
						this.factoryBeanObjectCache.put(beanName, (object != null ? object : NULL_OBJECT));
					}
				}
				return (object != NULL_OBJECT ? object : null);
			}
		}
		else {
			Object object = doGetObjectFromFactoryBean(factory, beanName);
			if (object != null && shouldPostProcess) {
				try {
					object = postProcessObjectFromFactoryBean(object, beanName);
				}
				catch (Throwable ex) {
					throw new BeanCreationException(beanName, "Post-processing of FactoryBean's object failed", ex);
				}
			}
			return object;
		}
	}
```
现在我们进入到doGetObjectFromFactoryBean方法中来查看最终的解析过程。发现这里的逻辑比较简单，基本上就是调用getObject方法返回。
```java
private Object doGetObjectFromFactoryBean(final FactoryBean<?> factory, final String beanName)
			throws BeanCreationException {

		Object object;
		try {
        	//当需要进行权限验证
			if (System.getSecurityManager() != null) {
				AccessControlContext acc = getAccessControlContext();
				try {
					object = AccessController.doPrivileged(new PrivilegedExceptionAction<Object>() {
						@Override
						public Object run() throws Exception {
								return factory.getObject();
							}
						}, acc);
				}
				catch (PrivilegedActionException pae) {
					throw pae.getException();
				}
			}
			else {
            	//调用factory的getObject方法来返回所需的bean
				object = factory.getObject();
			}
		}
		catch (FactoryBeanNotInitializedException ex) {
			throw new BeanCurrentlyInCreationException(beanName, ex.toString());
		}
		catch (Throwable ex) {
			throw new BeanCreationException(beanName, "FactoryBean threw exception on object creation", ex);
		}

		//	不允许获取的结果为null
		if (object == null && isSingletonCurrentlyInCreation(beanName)) {
			throw new BeanCurrentlyInCreationException(
					beanName, "FactoryBean which is currently in creation returned null from getObject");
		}
		return object;
	}
```
## 2.3 获取单例
前面我们通过`getSingleton(String beanName);`尝试从缓存中获取单例实例。当缓存中不存在时该方法返回null，此时需要通过其重载方法来从头开始获取。在这个方法中首先最后一次检查缓存中是否存在该beanName，当不存在时通过调用传入的ObjectFactory类的getObject方法来完成单例的初始化。在初始化前需要调用beforeSingletonCreation方法来记录该bean正在创建，初始化完成后还需要将其移除，最后将该单例放置到缓存中。
```java
public Object getSingleton(String beanName, ObjectFactory<?> singletonFactory) {
		Assert.notNull(beanName, "'beanName' must not be null");
		synchronized (this.singletonObjects) {
        	// 再次尝试从缓存中获取，如果缓存中不存在该bean再开始获取其单例
			Object singletonObject = this.singletonObjects.get(beanName);
			if (singletonObject == null) {
            	//检查是否有单例正在销毁
				if (this.singletonsCurrentlyInDestruction) {
					throw new BeanCreationNotAllowedException(beanName,
							"Singleton bean creation not allowed while the singletons of this factory are in destruction " +
							"(Do not request a bean from a BeanFactory in a destroy method implementation!)");
				}
				if (logger.isDebugEnabled()) {
					logger.debug("Creating shared instance of singleton bean '" + beanName + "'");
				}
                // 创建前的操作
				beforeSingletonCreation(beanName);
				boolean newSingleton = false;
				boolean recordSuppressedExceptions = (this.suppressedExceptions == null);
				if (recordSuppressedExceptions) {
					this.suppressedExceptions = new LinkedHashSet<Exception>();
				}
				try {
                	// 初始化
					singletonObject = singletonFactory.getObject();
					newSingleton = true;
				}
				catch (IllegalStateException ex) {
					// Has the singleton object implicitly appeared in the meantime ->
					// if yes, proceed with it since the exception indicates that state.
					singletonObject = this.singletonObjects.get(beanName);
					if (singletonObject == null) {
						throw ex;
					}
				}
				catch (BeanCreationException ex) {
					if (recordSuppressedExceptions) {
						for (Exception suppressedException : this.suppressedExceptions) {
							ex.addRelatedCause(suppressedException);
						}
					}
					throw ex;
				}
				finally {
					if (recordSuppressedExceptions) {
						this.suppressedExceptions = null;
					}
					afterSingletonCreation(beanName);
				}
				if (newSingleton) {
                	// 将beanName与其单例加入缓存
					addSingleton(beanName, singletonObject);
				}
			}
			return (singletonObject != NULL_OBJECT ? singletonObject : null);
		}
	}
```
我们回到调用getSingleton方法的位置，可以看到其getObject实际上调用的是AbstractBeanFactory类对象的createBean方法。该方法才是创建bean的方法。
```java
if (mbd.isSingleton()) {
					sharedInstance = getSingleton(beanName, new ObjectFactory<Object>() {
						@Override
						public Object getObject() throws BeansException {
							try {
								return createBean(beanName, mbd, args);
							}
							catch (BeansException ex) {
								destroySingleton(beanName);
								throw ex;
							}
						}
					});
					bean = getObjectForBeanInstance(sharedInstance, name, beanName, mbd);
				}
```
上面我们发现其实createBean方法才是创建bean的地方，现在我们进入到该方法中。在该方法中首先解析了Class，然后验证与准备覆盖的方法（子标签<lookup-method>等），然后调用了创建bean前的前置处理方法，最后开始创建bean。
```java
protected Object createBean(final String beanName, final RootBeanDefinition mbd, final Object[] args)
			throws BeanCreationException {

		if (logger.isDebugEnabled()) {
			logger.debug("Creating instance of bean '" + beanName + "'");
		}
		// 解析Class
		resolveBeanClass(mbd, beanName);

		// 对override属性进行标记与认证
		try {
			mbd.prepareMethodOverrides();
		}
		catch (BeanDefinitionValidationException ex) {
			throw new BeanDefinitionStoreException(mbd.getResourceDescription(),
					beanName, "Validation of method overrides failed", ex);
		}

		try {
			// 允许BeanPostProcessors返回一个代理来createBean代替bean实例
			Object bean = resolveBeforeInstantiation(beanName, mbd);
			if (bean != null) {
				return bean;
			}
		}
		catch (Throwable ex) {
			throw new BeanCreationException(mbd.getResourceDescription(), beanName,
					"BeanPostProcessor before instantiation of bean failed", ex);
		}
		
		Object beanInstance = doCreateBean(beanName, mbd, args);
		if (logger.isDebugEnabled()) {
			logger.debug("Finished creating instance of bean '" + beanName + "'");
		}
		return beanInstance;
	}
```
## 2.4 创建Bean的准备工作
经过前述的准备工作我们已经进入到了createBean方法中，在该方法中，调用doCreateBean才是真正真正进入到创建bean的方法，调用doCreateBean前都是在为创建bean进行统筹工作，主要分为以下几个步骤。
处理override属性
首先调用了RootBeanDefinition对象的prepareMethodOverrides方法进行对override属性的标记认证。
```java
	public void prepareMethodOverrides() throws BeanDefinitionValidationException {
		// 首先检查override属性是否存在
		MethodOverrides methodOverrides = getMethodOverrides();
		if (!methodOverrides.isEmpty()) {
			for (MethodOverride mo : methodOverrides.getOverrides()) {
				prepareMethodOverride(mo);
			}
		}
	}
    
    protected void prepareMethodOverride(MethodOverride mo) throws BeanDefinitionValidationException {
    	// 检查该类中该方法名的个数
		int count = ClassUtils.getMethodCountForName(getBeanClass(), mo.getMethodName());
		if (count == 0) {
			throw new BeanDefinitionValidationException(
					"Invalid method override: no method with name '" + mo.getMethodName() +
					"' on class [" + getBeanClassName() + "]");
		}
		else if (count == 1) {
			// 当个数为1时说明没有被覆盖，标记为没有被覆盖
			mo.setOverloaded(false);
		}
	}
```
实例化的前置处理
在调用doCreateBean前还调用了其前置处理方法resolveBeforeInstantiation，并且当前置处理方法的返回值不为null时直接返回前置处理的结果。
```java
	protected Object resolveBeforeInstantiation(String beanName, RootBeanDefinition mbd) {
		Object bean = null;
		if (!Boolean.FALSE.equals(mbd.beforeInstantiationResolved)) {
			// 如果还没有被解析
			if (!mbd.isSynthetic() && hasInstantiationAwareBeanPostProcessors()) {
				Class<?> targetType = determineTargetType(beanName, mbd);
				if (targetType != null) {
					bean = applyBeanPostProcessorsBeforeInstantiation(targetType, beanName);
					if (bean != null) {
						bean = applyBeanPostProcessorsAfterInitialization(bean, beanName);
					}
				}
			}
			mbd.beforeInstantiationResolved = (bean != null);
		}
		return bean;
	}
    
    protected Object applyBeanPostProcessorsBeforeInstantiation(Class<?> beanClass, String beanName)
			throws BeansException {

		for (BeanPostProcessor bp : getBeanPostProcessors()) {
			if (bp instanceof InstantiationAwareBeanPostProcessor) {
				InstantiationAwareBeanPostProcessor ibp = (InstantiationAwareBeanPostProcessor) bp;
                //调用处理器来修改bean
				Object result = ibp.postProcessBeforeInstantiation(beanClass, beanName);
				if (result != null) {
					return result;
				}
			}
		}
		return null;
	}
    
    public Object applyBeanPostProcessorsAfterInitialization(Object existingBean, String beanName)
			throws BeansException {

		Object result = existingBean;
		for (BeanPostProcessor beanProcessor : getBeanPostProcessors()) {
        	// 调用后处理器的处理方法
			result = beanProcessor.postProcessAfterInitialization(result, beanName);
			if (result == null) {
				return result;
			}
		}
		return result;
	}
```
## 2.5 创建bean
在前面我们已经完成了创建bean的准备工作，现在进入到doCreateBean方法查看，根据该方法的内容再针对其每一步进行研究
```java
	protected Object doCreateBean(final String beanName, final RootBeanDefinition mbd, final Object[] args) {
		// 实例化bean
		BeanWrapper instanceWrapper = null;
		if (mbd.isSingleton()) {
			instanceWrapper = this.factoryBeanInstanceCache.remove(beanName);
		}
		if (instanceWrapper == null) {
			instanceWrapper = createBeanInstance(beanName, mbd, args);
		}
		final Object bean = (instanceWrapper != null ? instanceWrapper.getWrappedInstance() : null);
		Class<?> beanType = (instanceWrapper != null ? instanceWrapper.getWrappedClass() : null);

		// 允许处理器加锁后调整
		synchronized (mbd.postProcessingLock) {
			if (!mbd.postProcessed) {
				applyMergedBeanDefinitionPostProcessors(mbd, beanType, beanName);
				mbd.postProcessed = true;
			}
		}

		// 是否是单例并且允许循环依赖并且正在创建
		boolean earlySingletonExposure = (mbd.isSingleton() && this.allowCircularReferences &&
				isSingletonCurrentlyInCreation(beanName));
		if (earlySingletonExposure) {
			if (logger.isDebugEnabled()) {
				logger.debug("Eagerly caching bean '" + beanName +
						"' to allow for resolving potential circular references");
			}
            // 为解决循环依赖，在bean初始化完成前将创建实例的ObjectFactory加入到工厂中
			addSingletonFactory(beanName, new ObjectFactory<Object>() {
				@Override
				public Object getObject() throws BeansException {
					return getEarlyBeanReference(beanName, mbd, bean);
				}
			});
		}

		// 实例化bean实例
		Object exposedObject = bean;
		try {
			populateBean(beanName, mbd, instanceWrapper);
			if (exposedObject != null) {
				exposedObject = initializeBean(beanName, exposedObject, mbd);
			}
		}
		catch (Throwable ex) {
			if (ex instanceof BeanCreationException && beanName.equals(((BeanCreationException) ex).getBeanName())) {
				throw (BeanCreationException) ex;
			}
			else {
				throw new BeanCreationException(mbd.getResourceDescription(), beanName, "Initialization of bean failed", ex);
			}
		}

		if (earlySingletonExposure) {
			Object earlySingletonReference = getSingleton(beanName, false);
			if (earlySingletonReference != null) {
				if (exposedObject == bean) {
					exposedObject = earlySingletonReference;
				}
				else if (!this.allowRawInjectionDespiteWrapping && hasDependentBean(beanName)) {
					String[] dependentBeans = getDependentBeans(beanName);
					Set<String> actualDependentBeans = new LinkedHashSet<String>(dependentBeans.length);
					for (String dependentBean : dependentBeans) {
						if (!removeSingletonIfCreatedForTypeCheckOnly(dependentBean)) {
							actualDependentBeans.add(dependentBean);
						}
					}
					if (!actualDependentBeans.isEmpty()) {
						throw new BeanCurrentlyInCreationException(beanName,
								"Bean with name '" + beanName + "' has been injected into other beans [" +
								StringUtils.collectionToCommaDelimitedString(actualDependentBeans) +
								"] in its raw version as part of a circular reference, but has eventually been " +
								"wrapped. This means that said other beans do not use the final version of the " +
								"bean. This is often the result of over-eager type matching - consider using " +
								"'getBeanNamesOfType' with the 'allowEagerInit' flag turned off, for example.");
					}
				}
			}
		}

		// Register bean as disposable.
		try {
			registerDisposableBeanIfNecessary(beanName, bean, mbd);
		}
		catch (BeanDefinitionValidationException ex) {
			throw new BeanCreationException(mbd.getResourceDescription(), beanName, "Invalid destruction signature", ex);
		}

		return exposedObject;
	}
```
### 2.5.1 创建bean实例
首先是通过createBeanInstance方法来创建bean实例并封装在BeanWrapper对象中。在该方法中，首先判断该bean配置文件中是否包含factory-method，如果设置了会根据其设置进行实例化。当没有设置时，首先需要确定使用bean对应类的哪一个构造器，在这里使用到了缓存机制，当已经进行构造则直接进行实例化。
```java
protected BeanWrapper createBeanInstance(String beanName, RootBeanDefinition mbd, Object[] args) {
		// 确保此时bean已经完成解析
		Class<?> beanClass = resolveBeanClass(mbd, beanName);

		if (beanClass != null && !Modifier.isPublic(beanClass.getModifiers()) && !mbd.isNonPublicAccessAllowed()) {
			throw new BeanCreationException(mbd.getResourceDescription(), beanName,
					"Bean class isn't public, and non-public access not allowed: " + beanClass.getName());
		}
		// 当工厂方法不为空时使用工厂方法进行初始化
		if (mbd.getFactoryMethodName() != null)  {
			return instantiateUsingFactoryMethod(beanName, mbd, args);
		}

		// 确定使用哪个构造函数
		boolean resolved = false;
		boolean autowireNecessary = false;
		if (args == null) {
			synchronized (mbd.constructorArgumentLock) {
            	// 锁定构造函数
				if (mbd.resolvedConstructorOrFactoryMethod != null) {
					resolved = true;
					autowireNecessary = mbd.constructorArgumentsResolved;
				}
			}
		}
        // 解析过则直接使用解析好的构造方法
		if (resolved) {
			if (autowireNecessary) {
            	// 使用带参数的构造器
				return autowireConstructor(beanName, mbd, null, null);
			}
			else {
            	// 使用不带参数的构造器
				return instantiateBean(beanName, mbd);
			}
		}

		// Need to determine the constructor...
		Constructor<?>[] ctors = determineConstructorsFromBeanPostProcessors(beanClass, beanName);
		if (ctors != null ||
				mbd.getResolvedAutowireMode() == RootBeanDefinition.AUTOWIRE_CONSTRUCTOR ||
				mbd.hasConstructorArgumentValues() || !ObjectUtils.isEmpty(args))  {
			return autowireConstructor(beanName, mbd, ctors, args);
		}

		// No special handling: simply use no-arg constructor.
		return instantiateBean(beanName, mbd);
	}
```
现在进入到
## 扩展
#### Spring使用
循环依赖
循环依赖指的是多个bean中互相之间持有对方而形成环。在Spring中存在两种依赖：构造器循环依赖、setter循环依赖。
构造器循环依赖无法解决只能抛出异常，其实现过程是维护一个“当前创建bean池”，当要创建的bean在“当前创建bean池”中时表示存在循环依赖
setter循环依赖中只能解决单例作用域的bean循环依赖，在该实现中，将完成构造器注入的bean提前暴露出一个单例工厂方法，从而其他的bean就能够引用到该bean，由此就解决了循环依赖问题
prototype范围的依赖
prototype范围的bean因为spring容器不对该bean进行缓存，也就无法提前对创建中的bean进行暴露。所以无法进行依赖注入
bean的不同scope
BeanWrapper与RootBeanDefinition